"""Phase 4 tests: entity_graph.py (session-scoped, evidence-linked Entity Graph) + analyzer/report/UI integration.
Offline; every test uses an isolated temporary database (never the real threat_memory.db)."""
import contextlib
import copy
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

import analyzer
import attack_dna as dna
import campaign_intel as ci
import entity_graph as eg
import investigation_agent as ia
import ioc_extract as ioc
import report
import risk
import tor_check
import tracker
from test_attack_dna import mk_result, _tmp_db

SENDER = "ceo.secret.mailbox@evil.example"
BODY = "SECRETBODYTEXT-should-never-be-stored"


def sid(n):
    return "SC-%032x" % n


def full(n, ip="8.8.4.4", url="http://evil.example/private/path?token=abc123", host="evil.example", **kw):
    """A scan result as analyzer.analyze_email() would hand it over, up to and including the evidence register."""
    r = mk_result(sid(n), **kw)
    r["parsed"]["from_addr"] = SENDER
    r["parsed"]["body_text"] = BODY
    r["iocs"]["urls"] = [{"url": url, "host": host, "suspicious": True, "risk": 0.8,
                          "flags": ["URL shortener hides the real destination"]}]
    r["geo"]["origin"].update({"ip": ip, "country": "Germany", "asn": "AS1", "infra": "hosting", "source": "test"})
    sink = []
    r["campaign_fingerprint"], r["campaign_matches"] = dna.find_matches(r, history_sink=sink)
    r["campaign_intel"] = ci.build_campaign_intel(r["campaign_fingerprint"], r["campaign_matches"], sink)
    r["evidence_register"], r["scan_findings"] = ia.build_scan_evidence(r)
    return r


def entity_rows(path):
    conn = sqlite3.connect(path)
    try:
        return (conn.execute("SELECT * FROM entity_edges").fetchall(), conn.execute("SELECT * FROM entity_meta").fetchall())
    finally:
        conn.close()


class Base(unittest.TestCase):
    def setUp(self):
        self.db = _tmp_db(self)


class EntityAndRelationshipCreation(Base):
    def test_expected_relationships_are_created_with_the_target_model_types(self):
        g = eg.build_entity_graph(full(1))
        self.assertEqual(g["status"], "ok")
        self.assertTrue(g["stored"])
        rels = {(e["src"]["type"], e["rel"], e["dst"]["type"]) for e in g["edges"]}
        for expected in (("email", "sent by", "sender"), ("sender", "at domain", "domain"), ("email", "from domain", "domain"),
                         ("email", "replies to", "domain"),
                         ("email", "return path", "domain"), ("email", "links to", "url"), ("url", "at host", "domain"),
                         ("email", "originated at", "ip"), ("email", "fingerprinted as", "campaign")):
            self.assertIn(expected, rels)

    def test_entity_ids_are_deterministic_within_a_session_and_typed(self):
        a = eg.build_entity_graph(full(1))
        b = eg.build_entity_graph(full(1))
        self.assertEqual([e["src"]["id"] for e in a["edges"]], [e["src"]["id"] for e in b["edges"]])
        for e in a["edges"]:
            for side in (e["src"], e["dst"]):
                self.assertRegex(side["id"], r"^(email|sender|domain|ip|url|campaign):[0-9a-f]{32}$")
                self.assertEqual(side["type"], side["id"].split(":")[0])

    def test_same_value_gets_one_entity_id_across_edges_no_duplicate_entities(self):
        g = eg.build_entity_graph(full(1))
        evil = {e["dst"]["id"] for e in g["edges"] if e["dst"]["type"] == "domain" and e["dst"]["label"] == "evil.example"}
        self.assertEqual(len(evil), 1)          # From/Reply-To/Return-Path/URL host are one and the same entity

    def test_networkx_view_reuses_the_edges(self):
        g = eg.build_entity_graph(full(1))
        G = eg.entity_digraph(g)
        self.assertEqual(G.number_of_edges(), len(g["edges"]))
        self.assertTrue(all("basis" in d and "evidence" in d for _u, _v, d in G.edges(data=True)))
        self.assertEqual(eg.entity_digraph(None).number_of_edges(), 0)


class EvidenceIntegrity(Base):
    def test_every_edge_cites_only_real_evidence_ids_of_this_scan(self):
        r = full(1)
        ids = {e["id"] for e in r["evidence_register"]}
        g = eg.build_entity_graph(r)
        self.assertTrue(g["edges"])
        for e in g["edges"]:
            self.assertTrue(e["evidence"])
            self.assertTrue(set(e["evidence"]) <= ids)
            self.assertEqual(e["scan_id"], r["scan_id"])

    def test_basis_and_provenance_follow_the_cited_evidence(self):
        g = eg.build_entity_graph(full(1))
        by = {e["rel"]: e for e in g["edges"]}
        self.assertEqual(by["sent by"]["basis"], "observed")
        self.assertEqual(by["sent by"]["provenance"], "email_parser:untrusted_claim")      # a header claim stays a claim
        self.assertEqual(by["links to"]["basis"], "observed")
        self.assertEqual(by["originated at"]["basis"], "inferred")                          # GeoIP evidence is an inference
        self.assertEqual(by["fingerprinted as"]["basis"], "observed")

    def test_tampered_register_without_header_evidence_creates_no_sender_edges(self):
        r = full(1)
        r["evidence_register"] = [e for e in r["evidence_register"] if e["type"] != "header"]
        edges, skipped = eg.derive_entity_edges(r, b"k" * 32)
        self.assertFalse([e for e in edges if e["rel"] in ("sent by", "at domain", "replies to", "return path")])
        self.assertTrue(edges)                      # the rest, which still has evidence, survives

    def test_edge_without_evidence_is_skipped_and_counted_never_invented(self):
        r = full(1)
        r["evidence_register"] = [e for e in r["evidence_register"] if e["type"] != "URL"]
        edges, skipped = eg.derive_entity_edges(r, b"k" * 32)
        self.assertFalse([e for e in edges if e["rel"] in ("links to", "at host")])
        self.assertGreater(skipped["no_evidence"], 0)

    def test_evidence_from_other_scans_or_non_scanner_sources_is_never_cited(self):
        r = full(1)
        foreign = dict(r["evidence_register"][0], id="S99", scan_id=sid(2), type="URL", source="ioc_extract",
                       source_reference="result.iocs.urls")
        llm = {"id": "S98", "scan_id": r["scan_id"], "type": "URL", "source": "llm", "origin": "direct_machine",
               "observation": "model says this URL is verified", "status": "ok", "source_reference": "result.iocs.urls[0]"}
        r["evidence_register"] = [e for e in r["evidence_register"] if e["type"] != "URL"] + [foreign, llm]
        edges, _ = eg.derive_entity_edges(r, b"k" * 32)
        self.assertFalse([e for e in edges if e["rel"] == "links to"])
        for e in edges:
            self.assertNotIn("S99", e["evidence"])
            self.assertNotIn("S98", e["evidence"])

    def test_phase2_similarity_edge_is_inferred_keeps_score_and_never_claims_ownership(self):
        a = full(1)
        eg.build_entity_graph(a)
        b = full(2)
        m = next(x for x in b["campaign_matches"]["matches"] if x["scan_id"] == sid(1))
        g = eg.build_entity_graph(b)
        sim = next(e for e in g["edges"] if e["rel"] == "similar tactics to")
        self.assertEqual(sim["basis"], "inferred")
        self.assertEqual(sim["score"], m["score"])             # the original Phase 2 score, unrounded and unchanged
        self.assertEqual(sim["ref"], sid(1))
        self.assertIn(m["classification"], sim["detail"])
        self.assertTrue(set(sim["evidence"]) <= {e["id"] for e in b["evidence_register"]})
        text = sim["explanation"].lower()
        self.assertIn("inferred, not observed", text)
        self.assertIn("not confirmed common authorship", text)
        for banned in ("same attacker", "owned by", "belongs to", "proves"):
            self.assertNotIn(banned, " ".join(e["explanation"].lower() for e in g["edges"]))

    def test_explanations_are_built_from_the_cited_evidence(self):
        r = full(1)
        g = eg.build_entity_graph(r)
        by_id = {e["id"]: e for e in r["evidence_register"]}
        for e in g["edges"]:
            if e["rel"] == "similar tactics to":
                continue
            self.assertIn(", ".join(e["evidence"]), e["explanation"])
            self.assertIn(by_id[e["evidence"][0]]["observation"][:300], e["explanation"])
        self.assertEqual(eg.explain_edge({}), "")
        self.assertEqual(eg.explain_edge(None), "")


class DuplicatesPersistenceAndHistory(Base):
    def test_rescanning_the_same_scan_does_not_duplicate_edges(self):
        r = full(1)
        eg.build_entity_graph(r)
        n1 = len(entity_rows(self.db)[0])
        eg.build_entity_graph(r)
        eg.build_entity_graph(r)
        self.assertEqual(len(entity_rows(self.db)[0]), n1)

    def test_rescan_replaces_that_scans_edges_with_the_current_derivation(self):
        r = full(1)
        eg.build_entity_graph(r)
        r2 = copy.deepcopy(r)
        r2["evidence_register"] = [e for e in r2["evidence_register"] if e["type"] != "URL"]
        g2 = eg.build_entity_graph(r2)
        rows = entity_rows(self.db)[0]
        self.assertEqual(len(rows), len(g2["edges"]))
        self.assertFalse([x for x in rows if x[6] == "links to"])

    def test_stored_rows_round_trip_with_evidence_and_timestamps(self):
        g = eg.build_entity_graph(full(1))
        rows = entity_rows(self.db)[0]
        self.assertEqual(len(rows), len(g["edges"]))
        conn = sqlite3.connect(self.db)
        try:
            for basis, ev, prov, at in conn.execute("SELECT basis, evidence_json, provenance, observed_at FROM entity_edges"):
                self.assertIn(basis, ("observed", "inferred"))
                self.assertTrue(re.match(r"^\[\"S\d+\"", ev))
                self.assertTrue(prov)
                self.assertRegex(at, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
        finally:
            conn.close()

    def test_shared_entities_connect_historical_scans_with_evidence_refs(self):
        eg.build_entity_graph(full(1))
        g2 = eg.build_entity_graph(full(2, ip="8.8.4.4"))
        shared = {(s["entity"]["type"], s["entity"]["label"]): s for s in g2["shared_entities"]}
        self.assertIn(("domain", "evil.example"), shared)
        self.assertIn(("ip", "8.8.4.4"), shared)
        for s in g2["shared_entities"]:
            for sc in s["scans"]:
                self.assertEqual(sc["scan_id"], sid(1))
                self.assertTrue(all(re.match(r"^SC-[0-9a-f]{32}:S\d+$", x) for x in sc["evidence"]))
        # an entity only this scan has is not reported as shared
        g3 = eg.build_entity_graph(full(3, ip="1.1.1.1", url="http://other.example/x", host="other.example", from_domain="o.example",
                                        reply_domain="o2.example", return_domain="o3.example"))
        labels = {s["entity"]["label"] for s in g3["shared_entities"] if s["entity"]["type"] != "sender"}
        self.assertNotIn("1.1.1.1", labels)

    def test_pruning_caps_stored_edges(self):
        with mock.patch.object(eg, "MAX_STORED_EDGES", 5):
            eg.build_entity_graph(full(1))
            eg.build_entity_graph(full(2))
        self.assertLessEqual(len(entity_rows(self.db)[0]), 5)

    def test_private_and_malformed_values_never_become_entities(self):
        for bad_ip in ("10.0.0.1", "192.168.1.1", "127.0.0.1", "999.1.1.1", "not-an-ip"):
            self.assertIsNone(eg._e_norm("ip", bad_ip))
        for bad in ("javascript:alert(1)", "ftp://x.example/a", "http://", "", 5, None):
            self.assertIsNone(eg._e_norm("url", bad))
        self.assertIsNone(eg._e_norm("domain", "bad domain"))
        self.assertIsNone(eg._e_norm("sender", "no-at-sign"))
        self.assertIsNone(eg._e_norm("email", "SC-1"))
        g = eg.build_entity_graph(full(1, ip="10.0.0.1"))
        self.assertFalse([e for e in g["edges"] if e["rel"] == "originated at"])


class SessionKey(Base):
    def test_key_is_random_hex_created_once_and_persisted(self):
        eg.build_entity_graph(full(1))
        eg.build_entity_graph(full(2))
        keys = [v for n, v in entity_rows(self.db)[1] if n == "hmac_key"]
        self.assertEqual(len(keys), 1)
        self.assertRegex(keys[0], r"^[0-9a-f]{64}$")

    def test_key_is_not_silently_regenerated_while_edges_depend_on_it(self):
        eg.build_entity_graph(full(1))
        before = entity_rows(self.db)
        conn = sqlite3.connect(self.db)
        conn.execute("DELETE FROM entity_meta")
        conn.commit()
        conn.close()
        g = eg.build_entity_graph(full(2))
        self.assertEqual(g["status"], "key_unavailable")
        self.assertEqual(g["edges"], [])
        self.assertEqual(entity_rows(self.db)[0], before[0])          # nothing written, nothing re-keyed
        self.assertEqual(entity_rows(self.db)[1], [])                 # and no replacement key was created
        conn = sqlite3.connect(self.db)
        conn.execute("INSERT INTO entity_meta (name, value) VALUES ('hmac_key', 'corrupt')")
        conn.commit()
        conn.close()
        self.assertEqual(eg.build_entity_graph(full(2))["status"], "key_unavailable")

    def test_missing_key_with_no_edges_is_created_fresh(self):
        eg.build_entity_graph(full(1))
        conn = sqlite3.connect(self.db)
        conn.execute("DELETE FROM entity_edges")
        conn.execute("DELETE FROM entity_meta")
        conn.commit()
        conn.close()
        self.assertEqual(eg.build_entity_graph(full(1))["status"], "ok")


class SessionIsolationAndPrivacy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for p in (mock.patch.object(tracker, "MULTIUSER", True), mock.patch.object(tracker, "SESSION_DIR", self.tmp.name),
                  mock.patch.object(tracker, "DB_FILE", os.path.join(self.tmp.name, "shared.db"))):
            p.start()
            self.addCleanup(p.stop)

    def _as(self, session, fn):
        with mock.patch.object(tracker, "_session_id", return_value=session):
            return fn()

    def test_another_session_sees_nothing_and_gets_different_ids(self):
        a = self._as("A", lambda: eg.build_entity_graph(full(1)))
        b = self._as("B", lambda: eg.build_entity_graph(full(2)))
        self.assertEqual(a["status"], "ok")
        self.assertEqual(b["status"], "ok")
        self.assertEqual(b["shared_entities"], [])                    # A's scan is invisible to B
        da = {e["dst"]["id"] for e in a["edges"] if e["dst"]["label"] == "evil.example"}
        db = {e["dst"]["id"] for e in b["edges"] if e["dst"]["label"] == "evil.example"}
        self.assertTrue(da and db and da.isdisjoint(db))              # per-session keys: same domain, different ids
        for session, n in (("A", 1), ("B", 2)):
            rows = self._as(session, lambda: sqlite3.connect(tracker._db_path(False)).execute("SELECT DISTINCT scan_id FROM entity_edges").fetchall())
            self.assertEqual(rows, [(sid(n),)])

    def test_same_session_still_correlates(self):
        self._as("A", lambda: eg.build_entity_graph(full(1)))
        g = self._as("A", lambda: eg.build_entity_graph(full(2)))
        self.assertTrue(g["shared_entities"])

    def test_nothing_is_written_to_the_shared_database(self):
        self._as("A", lambda: eg.build_entity_graph(full(1)))
        shared = tracker.DB_FILE
        if os.path.exists(shared):
            conn = sqlite3.connect(shared)
            try:
                tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            finally:
                conn.close()
            self.assertNotIn("entity_edges", tables)
            self.assertNotIn("entity_meta", tables)

    def test_deleting_session_data_removes_the_graph_and_its_key_together(self):
        self._as("A", lambda: eg.build_entity_graph(full(1)))
        self.assertTrue(self._as("A", tracker.delete_my_data))
        g = self._as("A", lambda: eg.build_entity_graph(full(2)))
        self.assertEqual(g["status"], "ok")
        self.assertEqual(g["shared_entities"], [])


class PrivacyAndFailSoft(Base):
    def test_no_sender_address_body_url_path_or_query_is_stored_or_returned(self):
        g = eg.build_entity_graph(full(1))
        blob = repr(entity_rows(self.db)) + repr(g)
        for secret in (SENDER, "ceo.secret.mailbox", BODY, "SECRETBODYTEXT", "/private/path", "token=abc123", "abc123"):
            self.assertNotIn(secret, blob)
        sender = next(e["dst"] for e in g["edges"] if e["rel"] == "sent by")
        self.assertIsNone(sender["label"])

    def test_database_failure_degrades_to_a_status_without_raising(self):
        with mock.patch.object(tracker, "get_connection", side_effect=RuntimeError("down")):
            g = eg.build_entity_graph(full(1))
        self.assertEqual(g["status"], "unavailable")
        self.assertEqual(g["edges"], [])

    def test_failed_save_still_returns_derived_edges_marked_not_stored(self):
        with mock.patch.object(eg, "_e_save", return_value=False):
            g = eg.build_entity_graph(full(1))
        self.assertEqual(g["status"], "persistence_failed")       # never presented as a successful, saved graph
        self.assertEqual(g["reason"], "save_failed")
        self.assertFalse(g["stored"])
        self.assertTrue(g["edges"])
        self.assertEqual(g["shared_entities"], [])

    def test_save_rolls_back_atomically_on_a_mid_write_error(self):
        eg.build_entity_graph(full(1))
        before = entity_rows(self.db)[0]
        r = full(1)
        key = eg._e_session_key(tracker.get_connection(shared=False))
        edges, _ = eg.derive_entity_edges(r, key)
        edges[-1] = dict(edges[-1], basis="bogus")                    # violates the CHECK constraint mid-batch
        conn = tracker.get_connection(shared=False)
        try:
            self.assertFalse(eg._e_save(conn, r["scan_id"], edges))
        finally:
            conn.close()
        self.assertEqual(entity_rows(self.db)[0], before)             # the previous edges survive intact

    def test_malformed_inputs_never_raise(self):
        for bad in (None, {}, [], "x", {"scan_id": "SC-1"}, {"scan_id": sid(1)}, {"scan_id": sid(1), "evidence_register": "x"},
                    {"scan_id": sid(1), "evidence_register": [None, 5, {"id": "S1"}], "parsed": "x", "iocs": [], "geo": 3}):
            g = eg.build_entity_graph(bad)
            self.assertIn(g["status"], ("insufficient_evidence", "no_edges"))      # unusable input is never reported as success
            self.assertEqual(g["edges"], [])

    def test_inputs_are_not_mutated(self):
        r = full(1)
        snap = copy.deepcopy(r)
        eg.build_entity_graph(r)
        self.assertEqual(r, snap)


class PipelineAndRendering(Base):
    RAW = b"From: a@example.com\r\nSubject: hi\r\n\r\nHello there, see http://evil.example/login for details.\r\n"

    def _scan(self):
        with mock.patch.object(tor_check, "maybe_update_tor_list", return_value=False):
            return analyzer.analyze_email(self.RAW, "a.eml")

    def test_analyzer_attaches_a_graph_that_cites_the_registers_own_ids(self):
        res = self._scan()
        g = res["entity_graph"]
        self.assertIn(g["status"], ("ok", "no_edges"))
        ids = {e["id"] for e in res["evidence_register"]}
        for e in g["edges"]:
            self.assertTrue(set(e["evidence"]) <= ids)

    def test_graph_never_changes_score_or_verdict_and_failure_cannot_break_a_scan(self):
        with mock.patch.object(tor_check, "maybe_update_tor_list", return_value=False):
            with mock.patch.object(analyzer, "entity_graph") as blocked:
                blocked.build_entity_graph.side_effect = RuntimeError("entity graph unavailable")
                without = analyzer.analyze_email(self.RAW, "a.eml")
            with_ = analyzer.analyze_email(self.RAW, "a.eml")
        self.assertIsNone(without["entity_graph"])
        self.assertEqual(without["score"], with_["score"])
        self.assertEqual(without["level"], with_["level"])
        self.assertEqual(without["evidence_register"], with_["evidence_register"])     # the register is not altered either

    def test_risk_module_does_not_reference_the_graph(self):
        with open(risk.__file__, encoding="utf-8") as f:
            self.assertNotIn("entity_graph", f.read())

    def test_report_section_lists_edges_evidence_and_no_secrets(self):
        r = full(1)
        r["entity_graph"] = eg.build_entity_graph(r)
        md = "\n".join(report.scan_evidence_md(r))
        self.assertIn("Entity graph (Phase 4)", md)
        self.assertIn("observed", md)
        for e in r["entity_graph"]["edges"]:
            self.assertIn(e["evidence"][0], md)
        for secret in (SENDER, "ceo.secret.mailbox", BODY, "token=abc123"):
            self.assertNotIn(secret, md)
        self.assertEqual(report.entity_graph_md({}), [])
        malformed = "\n".join(report.entity_graph_md({"entity_graph": {"edges": "x"}}))     # present but unusable: flagged, never silent
        self.assertIn("unrecognised state", malformed)
        self.assertNotIn("| Relationship |", malformed)

    def test_report_never_copies_other_scan_ids_or_their_evidence(self):
        eg.build_entity_graph(full(1))
        r = full(2)
        r["entity_graph"] = eg.build_entity_graph(r)
        self.assertTrue(r["entity_graph"]["shared_entities"])
        md = "\n".join(report.entity_graph_md(r))
        self.assertIn("Other retained scans", md)
        section = md[md.index("Entities also seen"):md.index("**Limitations:**")]
        self.assertNotIn("SC-", section)                  # the shared-entity table carries counts only, no scan ids or evidence refs
        self.assertNotIn(":S", section)

    def test_ui_panel_reads_precomputed_fields_only(self):
        base = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(base, "app.py"), encoding="utf-8") as f:
            src = f.read()
        start = src.index("# Phase 4: session-scoped entity graph, precomputed by analyzer.py")
        end = src.index("SHA-256 Cryptographic Evidence Hash", start)
        panel = src[start:end]
        self.assertIn('sel_res.get("entity_graph")', panel)
        for banned in ("build_entity_graph(", "get_connection(", "find_matches(", "save_fingerprint("):
            self.assertNotIn(banned, panel)


# ---------------------------------------------------------------------------------------------------------------------
# Correction 1: evidence attribution -- every relationship cites its OWN claim entry
# ---------------------------------------------------------------------------------------------------------------------
CLAIMS = {"from_address": "result.parsed.from_addr", "from_domain": "result.parsed.from_domain",
          "reply_to_domain": "result.parsed.reply_to_domain", "return_path_domain": "result.parsed.return_path_domain"}


def claim_entries(r):
    return {e["metadata"]["claim"]: e for e in r["evidence_register"] if isinstance(e.get("metadata"), dict) and e["metadata"].get("claim")}


class EvidenceAttribution(Base):
    def test_register_has_one_entry_per_claim_placed_between_phase2_and_phase3_sections(self):
        full(1)
        r = full(2)                                                                  # has a historical match, so Phase 3 entries exist
        ents = claim_entries(r)
        self.assertEqual(set(ents), set(CLAIMS))
        self.assertEqual(len({e["id"] for e in ents.values()}), 4)
        for claim, e in ents.items():
            self.assertEqual((e["type"], e["source"], e["origin"], e["status"]), ("header", "email_parser", "untrusted_claim", "ok"))
            self.assertEqual(e["source_reference"], CLAIMS[claim])
            self.assertEqual(e["scan_id"], r["scan_id"])
            self.assertNotIn("ceo.secret.mailbox", e["observation"])               # the local part is withheld
        reg = r["evidence_register"]
        ids = [int(e["id"][1:]) for e in reg]
        self.assertEqual(ids, list(range(1, len(ids) + 1)))                          # contiguous: nothing renumbered or skipped
        block = sorted(int(e["id"][1:]) for e in ents.values())
        self.assertEqual(block, list(range(block[0], block[0] + 4)))                 # one contiguous block, in claim order
        self.assertEqual([ents[c]["id"] for c in CLAIMS], ["S%d" % i for i in block])
        self.assertTrue(all(int(e["id"][1:]) < block[0] for e in reg if e["source"] == "attack_dna"))     # Phase 2 ids unchanged
        self.assertTrue(all(int(e["id"][1:]) > block[-1] for e in reg if e["source"] == "campaign_intel"))  # Phase 3 stays last
        self.assertTrue(any(e["source"] == "campaign_intel" for e in reg))

    def test_each_relationship_cites_exactly_its_own_claim_entry(self):
        r = full(1)
        ents = claim_entries(r)
        g = eg.build_entity_graph(r)
        expect = {"sent by": "from_address", "at domain": "from_address", "from domain": "from_domain",
                  "replies to": "reply_to_domain", "return path": "return_path_domain"}
        seen = set()
        for e in g["edges"]:
            if e["rel"] in expect:
                seen.add(e["rel"])
                self.assertEqual(e["evidence"], [ents[expect[e["rel"]]]["id"]], e["rel"])      # one id: its own, no neighbour
                if e["dst"]["type"] == "domain":
                    self.assertEqual(ents[expect[e["rel"]]]["metadata"]["domain"], e["dst"]["label"])
        self.assertEqual(seen, set(expect))

    def test_the_combined_header_entry_is_never_cited(self):
        r = full(1)
        combined = [e["id"] for e in r["evidence_register"] if " / " in str(e.get("source_reference"))
                    and e.get("source_reference", "").startswith("result.parsed.from_domain")]
        self.assertTrue(combined)
        for e in eg.build_entity_graph(r)["edges"]:
            self.assertFalse(set(e["evidence"]) & set(combined), e["rel"])

    def test_identical_domains_still_get_three_separate_evidence_entries(self):
        r = full(1, from_domain="same.example", reply_domain="same.example", return_domain="same.example")
        g = eg.build_entity_graph(r)
        by = {e["rel"]: e for e in g["edges"] if e["rel"] in ("from domain", "replies to", "return path")}
        self.assertEqual(len(by), 3)
        self.assertEqual(len({by[k]["dst"]["id"] for k in by}), 1)                    # one entity ...
        self.assertEqual(len({tuple(by[k]["evidence"]) for k in by}), 3)              # ... three distinct evidence references

    def test_removing_one_claim_removes_only_its_own_edges(self):
        r = full(1)
        gone = claim_entries(r)["reply_to_domain"]["id"]
        r["evidence_register"] = [e for e in r["evidence_register"] if e["id"] != gone]
        edges, skipped = eg.derive_entity_edges(r, b"k" * 32)
        rels = {e["rel"] for e in edges}
        self.assertNotIn("replies to", rels)
        for kept in ("sent by", "at domain", "from domain", "return path", "links to"):
            self.assertIn(kept, rels)
        self.assertGreaterEqual(skipped["no_evidence"], 1)

    def test_a_claim_about_another_value_or_kind_does_not_support_the_edge(self):
        for mutate in (lambda e: e["metadata"].update(domain="other.example"),          # same claim, different domain
                       lambda e: e.update(source_reference=CLAIMS["from_domain"]),      # right domain, wrong header field
                       lambda e: e["metadata"].update(claim="from_domain"),             # wrong claim kind
                       lambda e: e.update(status="missing"),
                       lambda e: e.update(source="llm")):
            r = full(1)
            mutate(claim_entries(r)["reply_to_domain"])
            self.assertNotIn("replies to", {e["rel"] for e in eg.derive_entity_edges(r, b"k" * 32)[0]})

    def test_sender_edges_need_the_address_claim_and_its_domain_must_match(self):
        r = full(1)
        claim_entries(r)["from_address"]["metadata"]["domain"] = "not-the-senders-domain.example"
        rels = {e["rel"] for e in eg.derive_entity_edges(r, b"k" * 32)[0]}
        self.assertFalse(rels & {"sent by", "at domain"})
        self.assertIn("from domain", rels)                                            # the From-domain claim is independent

    def test_older_register_without_claim_entries_degrades_openly_not_silently(self):
        r = full(1)
        r["evidence_register"] = [e for e in r["evidence_register"] if not isinstance(e.get("metadata"), dict) or not e["metadata"].get("claim")]
        g = eg.build_entity_graph(r)
        rels = {e["rel"] for e in g["edges"]}
        self.assertFalse(rels & {"sent by", "at domain", "from domain", "replies to", "return path"})
        self.assertIn("links to", rels)
        self.assertEqual(g["status"], "ok")
        self.assertGreater(g["skipped"]["no_evidence"], 0)
        self.assertIn("left out", eg.status_message(g)[1])                            # and the user is told


# ---------------------------------------------------------------------------------------------------------------------
# Correction 2: stale persistence / evidence-generation failure vs a valid empty graph
# ---------------------------------------------------------------------------------------------------------------------
def rows_for(path, scan):
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT COUNT(*) FROM entity_edges WHERE scan_id = ?", (scan,)).fetchone()[0]
    finally:
        conn.close()


def valid_but_empty(n):
    """A scan whose evidence register is perfectly usable but which has nothing linkable."""
    r = full(n)
    r["parsed"], r["iocs"], r["geo"] = {}, {"urls": []}, {}
    r["campaign_fingerprint"] = r["campaign_matches"] = None
    return r


class StalePersistence(Base):
    def test_a_valid_empty_reprocess_replaces_earlier_edges(self):
        eg.build_entity_graph(full(2))                                         # another scan must be untouched
        eg.build_entity_graph(full(1))
        self.assertGreater(rows_for(self.db, sid(1)), 0)
        n2 = rows_for(self.db, sid(2))
        g = eg.build_entity_graph(valid_but_empty(1))
        self.assertEqual((g["status"], g["edges"], g["stored"]), ("no_edges", [], True))
        self.assertEqual(rows_for(self.db, sid(1)), 0)                         # nothing outdated left behind for this scan
        self.assertEqual(rows_for(self.db, sid(2)), n2)

    def test_a_cleared_scan_stops_appearing_in_other_scans_history(self):
        eg.build_entity_graph(full(1))
        self.assertTrue(eg.build_entity_graph(full(2))["shared_entities"])
        eg.build_entity_graph(valid_but_empty(1))
        self.assertEqual(eg.build_entity_graph(full(2))["shared_entities"], [])

    def test_evidence_generation_failure_is_not_a_valid_empty_graph_and_keeps_old_edges_visibly(self):
        eg.build_entity_graph(full(1))
        before = entity_rows(self.db)[0]
        for label, mutate in (("builder error", lambda r: r.update(evidence_register=[], evidence_error="RuntimeError")),
                              ("no register", lambda r: r.pop("evidence_register")),
                              ("register not a list", lambda r: r.update(evidence_register="x")),
                              ("register of another scan", lambda r: r.update(evidence_register=[dict(e, scan_id=sid(9)) for e in r["evidence_register"]]))):
            with self.subTest(label):
                r = full(1)
                mutate(r)
                g = eg.build_entity_graph(r)
                self.assertEqual((g["status"], g["reason"], g["edges"]), ("insufficient_evidence", "evidence_unavailable", []))
                self.assertEqual(g["retained_previous_edges"], len(before))   # disclosed, not silently carried along
                self.assertEqual(entity_rows(self.db)[0], before)             # and not destroyed by a failed run
                self.assertIn("kept unchanged", eg.status_message(g)[1])

    def test_missing_scan_identity_is_insufficient_evidence_not_no_edges(self):
        r = full(1)
        r["scan_id"] = ""
        g = eg.build_entity_graph(r)
        self.assertEqual((g["status"], g["reason"]), ("insufficient_evidence", "no_scan_id"))

    def test_relationships_without_any_supporting_evidence_are_reported_and_old_edges_replaced(self):
        eg.build_entity_graph(full(1))
        r = full(1)
        keep = {"ML", "authentication", "BEC", "extortion", "validation"}
        r["evidence_register"] = [e for e in r["evidence_register"] if e["type"] in keep or e["source"] in ("header_analysis", "classifier")]
        g = eg.build_entity_graph(r)
        self.assertEqual((g["status"], g["reason"], g["edges"]), ("insufficient_evidence", "relationships_unsupported", []))
        self.assertGreater(g["skipped"]["no_evidence"], 0)
        self.assertEqual(rows_for(self.db, sid(1)), 0)                         # the current register cannot back the old edges
        self.assertNotIn("No relationships were detected", eg.status_message(g)[1])

    def test_three_situations_are_three_different_outcomes(self):
        outcomes = {eg.build_entity_graph(valid_but_empty(1))["status"]}
        r = full(1)
        r["evidence_error"] = "RuntimeError"
        outcomes.add(eg.build_entity_graph(r)["status"])
        outcomes.add(eg.build_entity_graph(full(1))["status"])
        self.assertEqual(outcomes, {"no_edges", "insufficient_evidence", "ok"})


# ---------------------------------------------------------------------------------------------------------------------
# Correction 3: every failure state is distinct, and never shown as "no relationships detected"
# ---------------------------------------------------------------------------------------------------------------------
def produce(status, test):
    """The real trigger for each status, through build_entity_graph(), each on its own fresh temporary database."""
    _tmp_db(test)
    r = full(1)
    if status == "ok":
        return eg.build_entity_graph(r)
    if status == "no_edges":
        return eg.build_entity_graph(valid_but_empty(1))
    if status == "insufficient_evidence":
        r["evidence_error"] = "RuntimeError"
        return eg.build_entity_graph(r)
    if status == "unavailable":
        with mock.patch.object(tracker, "get_connection", side_effect=RuntimeError("down")):
            return eg.build_entity_graph(r)
    if status == "key_unavailable":
        eg.build_entity_graph(r)
        conn = sqlite3.connect(tracker.DB_FILE)
        conn.execute("DELETE FROM entity_meta")
        conn.commit()
        conn.close()
        return eg.build_entity_graph(r)
    if status == "persistence_failed":
        with mock.patch.object(eg, "_e_save", return_value=False):
            return eg.build_entity_graph(r)
    if status == "error":
        with mock.patch.object(eg, "derive_entity_edges", side_effect=RuntimeError("boom")):
            return eg.build_entity_graph(r)
    raise AssertionError(status)


STATUSES = ("ok", "no_edges", "insufficient_evidence", "unavailable", "key_unavailable", "persistence_failed", "error")


class FailureTransparency(Base):
    def test_every_status_is_reachable_and_reports_itself(self):
        for st in STATUSES:
            with self.subTest(st):
                self.assertEqual(produce(st, self)["status"], st)

    def test_each_failure_has_its_own_message_and_none_reads_as_no_relationships(self):
        texts = {}
        for st in STATUSES:
            g = produce(st, self)
            level, text = eg.status_message(g)
            texts[st] = (level, text)
            if st not in ("ok", "no_edges"):
                self.assertIn(level, ("warning", "error"), st)
                self.assertNotIn("No relationships were detected", text, st)
                self.assertIn("not", text.lower(), st)
        self.assertEqual(texts["ok"], ("ok", ""))
        self.assertEqual(texts["no_edges"][0], "info")
        self.assertIn("No relationships were detected", texts["no_edges"][1])
        failures = [texts[s][1] for s in STATUSES if s not in ("ok", "no_edges")]
        self.assertEqual(len(set(failures)), len(failures))                        # five failure states, five different messages
        self.assertEqual(eg.status_message(None)[0], "warning")
        self.assertEqual(eg.status_message({"status": "???"})[0], "warning")

    def test_persistence_failure_still_shows_the_derived_edges_but_says_they_are_unsaved(self):
        g = produce("persistence_failed", self)
        self.assertTrue(g["edges"])
        self.assertFalse(g["stored"])
        self.assertIn("could not be saved", eg.status_message(g)[1])

    def test_report_states_each_failure_and_only_no_edges_says_none_detected(self):
        for st in STATUSES:
            with self.subTest(st):
                r = full(1)
                r["entity_graph"] = produce(st, self)
                md = "\n".join(report.entity_graph_md(r))
                self.assertIn("Entity graph (Phase 4)", md)
                if st in ("insufficient_evidence", "unavailable", "key_unavailable", "persistence_failed", "error"):
                    self.assertRegex(md, r"Entity graph (unavailable|incomplete)")
                    self.assertNotIn("No relationships were detected", md)
                if st == "no_edges":
                    self.assertIn("No relationships were detected", md)
                if st in ("ok", "persistence_failed"):
                    self.assertIn("| Relationship |", md)
                else:
                    self.assertNotIn("| Relationship |", md)

    def test_report_handles_missing_and_failed_builder_differently(self):
        self.assertEqual(report.entity_graph_md({}), [])                           # an older result with no graph key: nothing
        md = "\n".join(report.entity_graph_md({"entity_graph": None}))              # the analyzer's builder failed: say so
        self.assertIn("could not be computed", md)
        self.assertNotIn("No relationships were detected", md)

    def test_ui_panel_states_failures_and_is_read_only(self):
        base = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(base, "app.py"), encoding="utf-8") as f:
            src = f.read()
        start = src.index("# Phase 4: session-scoped entity graph, precomputed by analyzer.py")
        panel = src[start:src.index("SHA-256 Cryptographic Evidence Hash", start)]
        self.assertIn('"entity_graph" in sel_res', panel)
        self.assertIn("entity_graph.status_message(", panel)
        self.assertIn("st.error", panel)
        self.assertIn("st.warning", panel)
        self.assertIn("to_correlation_graph(", panel)
        for banned in ("build_entity_graph(", "get_connection(", "find_matches(", "save_fingerprint("):
            self.assertNotIn(banned, panel)

    def test_analyzer_failure_leaves_an_explicit_none_not_a_missing_graph(self):
        with mock.patch.object(tor_check, "maybe_update_tor_list", return_value=False):
            with mock.patch.object(analyzer, "entity_graph") as blocked:
                blocked.build_entity_graph.side_effect = RuntimeError("down")
                res = analyzer.analyze_email(PipelineAndRendering.RAW, "a.eml")
        self.assertIn("entity_graph", res)
        self.assertIsNone(res["entity_graph"])


# ---------------------------------------------------------------------------------------------------------------------
# Correction 4: the connected visualization (NetworkX -> the existing correlate.graph_figure)
# ---------------------------------------------------------------------------------------------------------------------
def with_fake_plotly(fn):
    """correlate.py imports plotly at module level and plotly is not installed here: import it against a recording fake so the
    REAL graph_figure() code (layout, node/edge loops, style lookups) runs on the adapter's output. Real drawing stays unverified."""
    go = mock.MagicMock()
    plotly = mock.MagicMock()
    plotly.graph_objects = go
    with mock.patch.dict("sys.modules", {"plotly": plotly, "plotly.graph_objects": go}):
        sys.modules.pop("correlate", None)
        import correlate
        return fn(correlate, go)


class Visualization(Base):
    def setUp(self):
        super().setUp()
        eg.build_entity_graph(full(1))
        self.g = eg.build_entity_graph(full(2))
        self.G = eg.to_correlation_graph(self.g)

    def test_adapter_uses_only_kinds_and_shape_graph_figure_draws(self):
        def check(corr, go):
            for _n, d in self.G.nodes(data=True):
                self.assertIn(d["kind"], corr.NODE_STYLE)            # an unknown kind would have edges drawn to invisible nodes
                self.assertTrue(d["label"])
            for _u, _v, d in self.G.edges(data=True):
                self.assertTrue(d["rel"])
        with_fake_plotly(check)

    def test_real_graph_figure_code_runs_on_the_adapter_output(self):
        def draw(corr, go):
            fig = corr.graph_figure(self.G, height=420)
            blob = repr(go.mock_calls)
            for _n, d in self.G.nodes(data=True):
                self.assertIn(d["label"], blob)                      # every node reached a trace (none silently dropped)
            return fig
        self.assertIsNotNone(with_fake_plotly(draw))

    def test_graph_is_connected_and_spans_the_shared_history(self):
        import networkx as nx
        self.assertTrue(nx.is_weakly_connected(self.G))
        kinds = {d["kind"] for _n, d in self.G.nodes(data=True)}
        self.assertTrue({"case", "email", "domain", "ip", "infra", "semantic"} <= kinds)
        self.assertTrue([n for n in self.G if n.startswith("scan:")])      # the other retained scan is drawn, linked via a shared entity
        self.assertTrue(any(d["rel"].startswith("also seen") for _u, _v, d in self.G.edges(data=True)))

    def test_parallel_relationships_merge_and_basis_and_score_are_visible(self):
        r = full(3, from_domain="same.example", reply_domain="same.example", return_domain="same.example")
        G = eg.to_correlation_graph(eg.build_entity_graph(r))
        merged = [d["rel"] for _u, _v, d in G.edges(data=True) if "replies to" in d["rel"]]
        self.assertEqual(len(merged), 1)
        self.assertIn(" / ", merged[0])
        inferred = [d for _u, _v, d in G.edges(data=True) if "(inferred)" in d["rel"]]
        self.assertTrue(inferred)
        self.assertTrue(any(isinstance(d.get("similarity"), float) for d in inferred))

    def test_adapter_tolerates_bad_input_and_needs_no_plotly(self):
        for bad in (None, {}, {"edges": "x"}, {"edges": [None, {"src": 1}]}, {"edges": [], "shared_entities": [None, {"entity": 3}]}):
            self.assertEqual(eg.to_correlation_graph(bad).number_of_nodes(), 0)
        with open(eg.__file__, encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("import plotly", src)
        self.assertNotIn("import correlate", src)


# ---------------------------------------------------------------------------------------------------------------------
# Correction 5: isolation against the REAL tracker.py (real _db_path / get_connection / _session_id / cleanup / delete)
# Only the module's constants are redirected to a temp dir; the Streamlit runtime that _session_id() reads is faked at the
# import boundary, so tracker's own code decides which database file each visitor gets.
# ---------------------------------------------------------------------------------------------------------------------
_CTX = threading.local()


@contextlib.contextmanager
def fake_streamlit_runtime():
    names = ("streamlit", "streamlit.runtime", "streamlit.runtime.scriptrunner")
    saved = {n: sys.modules.get(n) for n in names}
    scr = types.ModuleType("streamlit.runtime.scriptrunner")
    scr.get_script_run_ctx = lambda suppress_warning=False: (types.SimpleNamespace(session_id=_CTX.sid) if getattr(_CTX, "sid", None) else None)
    rt = types.ModuleType("streamlit.runtime")
    rt.scriptrunner = scr
    top = types.ModuleType("streamlit")
    top.runtime = rt
    sys.modules.update({"streamlit": top, "streamlit.runtime": rt, "streamlit.runtime.scriptrunner": scr})
    try:
        yield
    finally:
        for n, m in saved.items():
            if m is None:
                sys.modules.pop(n, None)
            else:
                sys.modules[n] = m


class RealTrackerIsolation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sessions = os.path.join(self.tmp.name, "sessions")
        patches = [mock.patch.object(tracker, "MULTIUSER", True), mock.patch.object(tracker, "SESSION_DIR", self.sessions),
                   mock.patch.object(tracker, "DB_FILE", os.path.join(self.tmp.name, "shared.db")),
                   mock.patch.object(tracker, "_last_cleanup", 0.0), fake_streamlit_runtime()]
        for p in patches:
            p.__enter__()
            self.addCleanup(p.__exit__, None, None, None)
        _CTX.sid = None
        self.addCleanup(setattr, _CTX, "sid", None)

    def run_as(self, session, n, **kw):
        _CTX.sid = session
        r = full(n, **kw)
        return r, eg.build_entity_graph(r)

    def path_of(self, session):
        _CTX.sid = session
        return tracker._db_path(False)

    def key_of(self, session):
        conn = sqlite3.connect(self.path_of(session))
        try:
            return conn.execute("SELECT value FROM entity_meta WHERE name = 'hmac_key'").fetchone()[0]
        finally:
            conn.close()

    def test_each_visitor_gets_a_distinct_database_file_with_only_their_own_scans(self):
        _, ga = self.run_as("visitor-A", 1)
        _, gb = self.run_as("visitor-B", 2)
        pa, pb = self.path_of("visitor-A"), self.path_of("visitor-B")
        self.assertNotEqual(pa, pb)
        self.assertTrue(pa.startswith(self.sessions) and pb.startswith(self.sessions))
        for path, n in ((pa, 1), (pb, 2)):
            conn = sqlite3.connect(path)
            try:
                self.assertEqual(conn.execute("SELECT DISTINCT scan_id FROM entity_edges").fetchall(), [(sid(n),)])
            finally:
                conn.close()
        self.assertEqual(gb["shared_entities"], [])                          # B's same-domain scan cannot see A's
        self.assertNotEqual(self.key_of("visitor-A"), self.key_of("visitor-B"))
        da = {e["dst"]["id"] for e in ga["edges"] if e["dst"]["label"] == "evil.example"}
        db = {e["dst"]["id"] for e in gb["edges"] if e["dst"]["label"] == "evil.example"}
        self.assertTrue(da and db and da.isdisjoint(db))

    def test_the_shared_database_never_receives_graph_tables_and_session_files_are_private(self):
        self.run_as("visitor-A", 1)
        if os.path.exists(tracker.DB_FILE):
            conn = sqlite3.connect(tracker.DB_FILE)
            try:
                tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
            finally:
                conn.close()
            self.assertFalse(tables & {"entity_edges", "entity_meta"})
        if os.name == "posix":
            self.assertEqual(os.stat(self.path_of("visitor-A")).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(self.sessions).st_mode & 0o777, 0o700)

    def test_the_same_visitor_still_correlates_across_scans(self):
        self.run_as("visitor-A", 1)
        _, g = self.run_as("visitor-A", 2)
        self.assertTrue(g["shared_entities"])
        self.assertEqual(g["status"], "ok")

    def test_no_identifiable_session_means_nothing_is_stored_and_the_failure_is_reported(self):
        r, g = self.run_as(None, 1)                                           # tracker falls back to a throw-away in-memory database
        self.assertEqual(tracker._db_path(False), ":memory:")
        self.assertEqual((g["status"], g["reason"], g["stored"]), ("persistence_failed", "no_session_storage", False))
        self.assertTrue(g["edges"])                                           # still shown, but not claimed as saved
        self.assertIn("no session storage", eg.status_message(g)[1])
        self.assertFalse(os.path.isdir(self.sessions) and os.listdir(self.sessions))
        _, g2 = self.run_as(None, 2)
        self.assertEqual(g2["shared_entities"], [])                           # and nothing leaks between such callers either

    def test_delete_my_data_removes_only_that_visitors_graph_and_key(self):
        self.run_as("visitor-A", 1)
        self.run_as("visitor-B", 2)
        key_b = self.key_of("visitor-B")
        _CTX.sid = "visitor-A"
        self.assertTrue(tracker.delete_my_data())
        self.assertFalse(os.path.exists(self.path_of("visitor-A")))
        self.assertEqual(self.key_of("visitor-B"), key_b)
        _, g = self.run_as("visitor-A", 3)
        self.assertEqual((g["status"], g["shared_entities"]), ("ok", []))     # a fresh session: fresh key, no old edges

    def test_idle_session_cleanup_removes_graph_and_key_together(self):
        self.run_as("visitor-A", 1)
        key_a = self.key_of("visitor-A")
        old = time.time() - tracker.SESSION_TTL_SECONDS - 60
        os.utime(self.path_of("visitor-A"), (old, old))
        tracker._last_cleanup = 0.0
        self.run_as("visitor-B", 2)                                           # B's activity triggers tracker's own cleanup pass
        self.assertFalse(os.path.exists(self.path_of("visitor-A")))
        _, g = self.run_as("visitor-A", 3)
        self.assertEqual(g["shared_entities"], [])
        self.assertNotEqual(self.key_of("visitor-A"), key_a)
        self.assertEqual(rows_for(self.path_of("visitor-B"), sid(2)) > 0, True)

    def test_concurrent_visitors_on_separate_threads_never_see_each_other(self):
        results, errors = {}, []

        def visitor(name, base):
            try:
                _CTX.sid = name
                out = []
                for i in range(3):
                    r = full(base + i)
                    out.append(eg.build_entity_graph(r))
                results[name] = out
            except Exception as exc:                                          # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=visitor, args=("T-A", 10)), threading.Thread(target=visitor, args=("T-B", 20))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        for name, base in (("T-A", 10), ("T-B", 20)):
            own = {sid(base + i) for i in range(3)}
            for g in results[name]:
                self.assertEqual(g["status"], "ok")
                for s in g["shared_entities"]:
                    self.assertTrue({x["scan_id"] for x in s["scans"]} <= own)
            conn = sqlite3.connect(self.path_of(name))
            try:
                self.assertEqual({r[0] for r in conn.execute("SELECT DISTINCT scan_id FROM entity_edges")}, own)
            finally:
                conn.close()


# ---------------------------------------------------------------------------------------------------------------------
# Final review fix: a URL relationship needs EXACT per-item evidence whose host matches the URL; the aggregate entry never counts
# ---------------------------------------------------------------------------------------------------------------------
TOKEN = "SECRETTOKEN-9f3a"


def url_item(host, path="/p", flagged=True, listed_host=None):
    return {"url": "http://%s%s?token=%s" % (host, path, TOKEN), "host": listed_host or host, "suspicious": flagged,
            "risk": 0.9 if flagged else 0.0, "flags": ["URL shortener hides the real destination"] if flagged else []}


def with_urls(n, urls, base=None):
    """The scan result with these extracted URLs and a register built from them by the real builder."""
    r = base or full(n)
    r["iocs"]["urls"] = urls
    r["evidence_register"], r["scan_findings"] = ia.build_scan_evidence(r)
    return r


def per_item(r):
    return {e["source_reference"]: e for e in r["evidence_register"] if str(e.get("source_reference")).startswith("result.iocs.urls[")}


def aggregate_ids(r):
    return {e["id"] for e in r["evidence_register"] if e.get("source_reference") == "result.iocs.urls"}


def url_edges(g):
    """The URL relationships of a graph dict, or of a raw edge list as returned by derive_entity_edges()."""
    return [e for e in (g["edges"] if isinstance(g, dict) else g) if e["rel"] in ("links to", "at host")]


class UrlEvidenceIntegrity(Base):
    def dump(self):
        return repr(entity_rows(self.db))

    def assert_nothing_unsupported_persisted(self, g, *gone):
        rows = sqlite3.connect(self.db).execute("SELECT src_type, dst_type, src_label, dst_label FROM entity_edges").fetchall()
        for text in gone:
            self.assertNotIn(text, self.dump())
            self.assertNotIn(text, repr(g))
        self.assertEqual(len(rows), len(g["edges"]))                       # exactly what was derived, nothing more is stored

    def test_unflagged_url_with_only_aggregate_evidence_creates_no_relationship(self):
        r = with_urls(1, [url_item("quiet.example", "/quiet", flagged=False)])
        self.assertTrue(aggregate_ids(r))                                  # precondition: the aggregate entry exists ...
        self.assertEqual(per_item(r), {})                                  # ... and there is no per-item entry
        g = eg.build_entity_graph(r)
        self.assertEqual(url_edges(g), [])
        self.assertGreaterEqual(g["skipped"]["no_evidence"], 2)            # links to + at host, both counted
        self.assertFalse(set().union(*[set(e["evidence"]) for e in g["edges"]]) & aggregate_ids(r))
        self.assert_nothing_unsupported_persisted(g, "quiet.example", "/quiet", TOKEN)
        self.assertIn("left out", eg.status_message(g)[1])

    def test_ninth_flagged_url_without_its_own_evidence_is_skipped(self):
        urls = [url_item("h%d.example" % i, "/p%d" % i) for i in range(9)]
        r = with_urls(1, urls)
        self.assertEqual(sorted(per_item(r)), ["result.iocs.urls[%d]" % i for i in range(8)])    # the register stops at eight
        g = eg.build_entity_graph(r)
        self.assertEqual({e["dst"]["label"] for e in g["edges"] if e["rel"] == "at host"}, {"h%d.example" % i for i in range(8)})
        self.assertEqual(len([e for e in g["edges"] if e["rel"] == "links to"]), 8)
        self.assertEqual(g["skipped"]["no_evidence"], 2)                    # exactly the ninth URL's two relationships
        items = per_item(r)
        cited = [tuple(e["evidence"]) for e in g["edges"] if e["rel"] == "links to"]
        self.assertEqual(sorted(cited), sorted((items["result.iocs.urls[%d]" % i]["id"],) for i in range(8)))   # each cites only its own entry
        for e in url_edges(g):
            self.assertEqual(len(e["evidence"]), 1)
        self.assert_nothing_unsupported_persisted(g, "h8.example", "/p8")

    def test_mismatched_url_host_and_evidence_metadata_creates_nothing(self):
        # (a) the evidence entry's recorded host is changed
        r = with_urls(1, [url_item("real.example")])
        per_item(r)["result.iocs.urls[0]"]["metadata"]["host"] = "other.example"
        ga = eg.build_entity_graph(r)
        # (b) the URL itself differs from what the entry was recorded for
        r2 = with_urls(2, [url_item("real.example")])
        r2["iocs"]["urls"][0]["url"] = "http://swapped.example/x?token=" + TOKEN
        gb = eg.build_entity_graph(r2)
        # (c) the extractor's separate 'host' field disagrees with the URL's real host (the entry records that decoy)
        r3 = with_urls(3, [url_item("actual.example", listed_host="decoy.example")])
        self.assertEqual(per_item(r3)["result.iocs.urls[0]"]["metadata"]["host"], "decoy.example")
        gc = eg.build_entity_graph(r3)
        for g in (ga, gb, gc):
            self.assertEqual(url_edges(g), [])
            self.assertGreaterEqual(g["skipped"]["no_evidence"], 2)
        for text in ("real.example", "other.example", "swapped.example", "actual.example", "decoy.example", TOKEN):
            self.assertNotIn(text, self.dump() + repr((ga, gb, gc)).replace("evil.example", ""))

    def test_valid_per_item_evidence_creates_both_edges_citing_the_items_own_entry(self):
        r = with_urls(1, [url_item("alpha.example", "/one"), url_item("alpha.example", "/two"), url_item("beta.example", "/three")])
        items = per_item(r)
        g = eg.build_entity_graph(r)
        self.assertEqual(g["skipped"]["no_evidence"], 0)
        links = [e for e in g["edges"] if e["rel"] == "links to"]
        hosts = [e for e in g["edges"] if e["rel"] == "at host"]
        self.assertEqual((len(links), len(hosts)), (3, 3))
        cited = {tuple(e["evidence"]) for e in links}
        self.assertEqual(cited, {(items["result.iocs.urls[%d]" % i]["id"],) for i in range(3)})    # three URLs, three different entries
        for e in links + hosts:
            self.assertEqual((e["basis"], e["provenance"]), ("observed", "ioc_extract:direct_machine"))
            entry = next(x for x in r["evidence_register"] if x["id"] == e["evidence"][0])
            self.assertEqual(len(e["evidence"]), 1)
            host = e["dst"]["label"] if e["rel"] == "at host" else entry["metadata"]["host"]
            self.assertEqual(entry["metadata"]["host"], host.replace("URL ", ""))
        self.assertEqual({e["dst"]["label"] for e in hosts}, {"alpha.example", "beta.example"})

    def test_a_per_item_entry_must_be_the_scanners_ok_entry_for_that_exact_index(self):
        for label, mutate in (("wrong source", lambda r, e: e.update(source="llm")),
                              ("not ok", lambda r, e: e.update(status="failed")),
                              ("wrong type", lambda r, e: e.update(type="header")),
                              ("wrong index", lambda r, e: e.update(source_reference="result.iocs.urls[1]")),
                              ("no metadata", lambda r, e: e.update(metadata=None)),
                              ("host not text", lambda r, e: e["metadata"].update(host=7))):
            with self.subTest(label):
                r = with_urls(1, [url_item("real.example")])
                mutate(r, per_item(r)["result.iocs.urls[0]"])
                self.assertEqual(url_edges(eg.derive_entity_edges(r, b"k" * 32)[0]), [])

    def test_the_aggregate_entry_is_never_cited_by_any_edge(self):
        for r in (full(1), with_urls(2, [url_item("quiet.example", flagged=False)]),
                  with_urls(3, [url_item("h%d.example" % i) for i in range(9)])):
            cited = set()
            for e in eg.derive_entity_edges(r, b"k" * 32)[0]:
                cited |= set(e["evidence"])
            self.assertFalse(cited & aggregate_ids(r))

    def test_losing_per_item_evidence_removes_the_stored_url_edges_and_says_so(self):
        eg.build_entity_graph(with_urls(1, [url_item("real.example")]))
        self.assertTrue(sqlite3.connect(self.db).execute("SELECT COUNT(*) FROM entity_edges WHERE src_type='url' OR dst_type='url'").fetchone()[0])
        r = with_urls(1, [url_item("real.example")])
        r["evidence_register"] = [e for e in r["evidence_register"] if not str(e.get("source_reference")).startswith("result.iocs.urls[")]
        g = eg.build_entity_graph(r)
        self.assertEqual(g["status"], "ok")
        self.assertGreaterEqual(g["skipped"]["no_evidence"], 2)
        self.assertEqual(sqlite3.connect(self.db).execute("SELECT COUNT(*) FROM entity_edges WHERE src_type='url' OR dst_type='url'").fetchone()[0], 0)

    def test_a_scan_whose_only_links_are_unsupported_is_not_reported_as_clean(self):
        r = valid_but_empty(1)
        r["iocs"]["urls"] = [url_item("quiet.example", flagged=False)]
        r["evidence_register"], r["scan_findings"] = ia.build_scan_evidence(r)
        g = eg.build_entity_graph(r)
        self.assertEqual((g["status"], g["reason"], g["edges"]), ("insufficient_evidence", "relationships_unsupported", []))
        self.assertNotIn("No relationships were detected", eg.status_message(g)[1])
        self.assertEqual(rows_for(self.db, sid(1)), 0)

    def test_supported_urls_still_persist_only_the_host_never_path_query_or_token(self):
        r = with_urls(1, [url_item("alpha.example", "/private/segment")])
        g = eg.build_entity_graph(r)
        self.assertTrue(url_edges(g))
        for text in ("/private/segment", "private", "token=", TOKEN, "http://alpha.example"):
            self.assertNotIn(text, self.dump() + repr(g))


# ---------------------------------------------------------------------------------------------------------------------
# Final evidence-integrity correction: strict provenance for URL, header-claim and GeoIP evidence
# ---------------------------------------------------------------------------------------------------------------------
BAD_ORIGINS = ("llm", "inference", "historical", "trusted_external", "untrusted_claim", "direct_machine", None, "")
# the ONLY (type, source, origin) combinations an edge may ever cite
ALLOWED_PROVENANCE = {("URL", "ioc_extract", "direct_machine"), ("header", "email_parser", "untrusted_claim"),
                      ("GeoIP", "geolocate", "inference"), ("campaign fingerprint", "attack_dna", "direct_machine"),
                      ("campaign fingerprint", "attack_dna", "historical")}


def rebuild(r):
    r["evidence_register"], r["scan_findings"] = ia.build_scan_evidence(r)
    return r


def geo_entry(r):
    return next(e for e in r["evidence_register"] if e.get("type") == "GeoIP" and e.get("source_reference") == "result.geo.origin")


def rels_of(r):
    return {e["rel"] for e in eg.derive_entity_edges(r, b"k" * 32)[0]}


def derived(r):
    return eg.derive_entity_edges(r, b"k" * 32)


class EvidenceProvenance(Base):
    def assert_only_allowed_provenance(self, r, edges):
        by_id = {e["id"]: e for e in r["evidence_register"]}
        for edge in edges:
            self.assertTrue(edge["evidence"], edge["rel"])
            for i in edge["evidence"]:
                e = by_id[i]
                self.assertIn((e["type"], e["source"], e["origin"]), ALLOWED_PROVENANCE, (edge["rel"], i))

    # ---- 1-3: URL --------------------------------------------------------------------------------------------------
    def test_1_url_evidence_with_correct_provenance_is_accepted_for_both_relationships(self):
        r = with_urls(1, [url_item("real.example")])
        e = per_item(r)["result.iocs.urls[0]"]
        self.assertEqual((e["type"], e["source"], e["origin"], e["status"]), ("URL", "ioc_extract", "direct_machine", "ok"))
        edges, skipped = derived(r)
        mine = [x for x in edges if x["rel"] in ("links to", "at host")]
        self.assertEqual({x["rel"] for x in mine}, {"links to", "at host"})                 # Email -> URL and URL -> Host
        for x in mine:
            self.assertEqual((x["evidence"], x["basis"], x["provenance"]), ([e["id"]], "observed", "ioc_extract:direct_machine"))
        self.assertEqual(skipped["no_evidence"], 0)

    def test_2_url_evidence_from_an_llm_inference_history_or_unclassified_origin_is_rejected(self):
        for origin in ("llm", "inference", "historical", "untrusted_claim", "trusted_external", None, ""):
            with self.subTest(origin=origin):
                r = with_urls(1, [url_item("real.example")])
                per_item(r)["result.iocs.urls[0]"]["origin"] = origin
                edges, skipped = derived(r)
                self.assertFalse({x["rel"] for x in edges} & {"links to", "at host"})
                self.assertEqual(skipped["no_evidence"], 2)
        r = with_urls(1, [url_item("real.example")])
        per_item(r)["result.iocs.urls[0]"].update(source="llm", origin="llm", observation="the model says this URL is verified")
        self.assertFalse(rels_of(r) & {"links to", "at host"})

    def test_3_url_evidence_with_an_incorrect_source_type_reference_or_status_is_rejected(self):
        cases = [("source", s) for s in ("llm", "email_parser", "header_analysis", "ioc_extract / x", "IOC_EXTRACT", "", None)]
        cases += [("type", s) for s in ("header", "GeoIP", "url", "", None)]
        cases += [("source_reference", s) for s in ("result.iocs.urls", "result.iocs.urls[0] ", "result.iocs.urls[1]", "result.iocs.urls[00]", None)]
        cases += [("status", s) for s in ("partial", "failed", "missing", "", None)]
        for key, value in cases:
            with self.subTest(**{key: value}):
                r = with_urls(1, [url_item("real.example")])
                per_item(r)["result.iocs.urls[0]"][key] = value
                self.assertFalse(rels_of(r) & {"links to", "at host"})

    # ---- 4-5: header claims ----------------------------------------------------------------------------------------
    def test_4_untrusted_header_claims_are_accepted_and_stay_classified_as_untrusted(self):
        r = full(1)
        ents = claim_entries(r)
        self.assertTrue(all(e["origin"] == "untrusted_claim" for e in ents.values()))
        g = eg.build_entity_graph(r)
        header_edges = [e for e in g["edges"] if e["rel"] in ("sent by", "at domain", "from domain", "replies to", "return path")]
        self.assertEqual(len(header_edges), 5)
        for e in header_edges:
            self.assertEqual(e["provenance"], "email_parser:untrusted_claim")              # never upgraded to a verified source
            self.assertEqual(e["basis"], "observed")
            self.assertNotIn("direct_machine", e["provenance"] + e["explanation"])
            self.assertNotIn("trusted_external", e["provenance"] + e["explanation"])
            self.assertIn("untrusted_claim", e["explanation"])

    def test_5_header_evidence_with_an_incorrect_origin_source_or_type_is_rejected(self):
        owns = {"from_address": {"sent by", "at domain"}, "from_domain": {"from domain"}, "reply_to_domain": {"replies to"},
                "return_path_domain": {"return path"}}
        every = set().union(*owns.values())
        mutations = [("origin", o) for o in ("direct_machine", "trusted_external", "inference", "historical", "llm", None, "")]
        mutations += [("source", s) for s in ("llm", "header_analysis", "email_parser / header_analysis", "", None)]
        mutations += [("type", s) for s in ("URL", "Header", "", None)]
        for claim, own in owns.items():
            for key, value in mutations:
                with self.subTest(claim=claim, **{key: value}):
                    r = full(1)
                    claim_entries(r)[claim][key] = value
                    rels = rels_of(r)
                    self.assertFalse(rels & own)                                          # exactly that claim's relationships go ...
                    self.assertEqual(rels & every, every - own)                           # ... and the other claims' remain

    # ---- 6-9: GeoIP ------------------------------------------------------------------------------------------------
    def test_6_correct_geoip_evidence_with_a_matching_ip_is_accepted(self):
        r = full(1)
        e = geo_entry(r)
        self.assertEqual((e["type"], e["source"], e["origin"], e["status"]), ("GeoIP", "geolocate", "inference", "ok"))
        self.assertEqual(e["metadata"]["ip"], "8.8.4.4")
        edges, _ = derived(r)
        edge = next(x for x in edges if x["rel"] == "originated at")
        self.assertEqual((edge["evidence"], edge["basis"], edge["provenance"]), ([e["id"]], "inferred", "geolocate:inference"))
        self.assertEqual(edge["dst"]["label"], "8.8.4.4")
        e["status"] = "partial"                                                             # an unresolved country is still the same IP
        self.assertIn("originated at", rels_of(r))

    def test_6b_ip_matching_uses_real_parsing_not_text_comparison(self):
        r = full(1, ip="2001:4860:4860:0:0:0:0:8888")                                          # long form on the scan side
        self.assertEqual(geo_entry(r)["metadata"]["ip"], "2001:4860:4860:0:0:0:0:8888")
        edge = next(x for x in derived(r)[0] if x["rel"] == "originated at")
        self.assertEqual(edge["dst"]["label"], "2001:4860:4860::8888")                       # normalised entity
        for spelling in ("2001:4860:4860::8888", "2001:4860:4860:0000:0000:0000:0000:8888", "2001:4860:4860::8888 ", "2001:4860:4860::8888".upper()):
            with self.subTest(spelling=spelling):
                geo_entry(r)["metadata"]["ip"] = spelling
                self.assertIn("originated at", rels_of(r))

    def test_7_geoip_evidence_for_a_different_ip_is_rejected_and_never_substituted(self):
        for other in ("1.1.1.1", "8.8.4.44", "18.8.4.4", "8.8.4.40", "8.8.4.4.1", "8.8.4.4 (approx)", "2001:4860:4860::8888", "::ffff:8.8.4.4"):
            with self.subTest(other=other):
                r = full(1)
                geo_entry(r)["metadata"]["ip"] = other                                       # the observation text still says 8.8.4.4
                edges, skipped = derived(r)
                self.assertNotIn("originated at", {x["rel"] for x in edges})
                self.assertEqual(skipped["no_evidence"], 1)
        r = full(1)
        right = geo_entry(r)
        decoy = dict(right, id="S98", metadata=dict(right["metadata"], ip="1.1.1.1"))        # another IP's entry listed FIRST
        r["evidence_register"] = [decoy] + r["evidence_register"]
        edge = next(x for x in derived(r)[0] if x["rel"] == "originated at")
        self.assertEqual(edge["evidence"], [right["id"]])
        r["evidence_register"] = [decoy] + [e for e in r["evidence_register"] if e["id"] != right["id"]]
        self.assertNotIn("originated at", rels_of(r))                                        # only the decoy exists: no edge at all

    def test_8_missing_or_malformed_structured_ip_metadata_is_rejected(self):
        for label, meta in (("none", None), ("empty", {}), ("ip none", {"ip": None}), ("ip empty", {"ip": ""}), ("ip int", {"ip": 5}),
                            ("ip list", {"ip": ["8.8.4.4"]}), ("ip garbage", {"ip": "garbage"}), ("other keys only", {"approximate": True}),
                            ("private ip", {"ip": "10.0.0.1"}), ("metadata not a mapping", "8.8.4.4")):
            with self.subTest(label):
                r = full(1)
                e = geo_entry(r)
                self.assertIn("8.8.4.4", e["observation"])                                   # the text has the IP; it must not be used
                e["metadata"] = meta
                edges, skipped = derived(r)
                self.assertNotIn("originated at", {x["rel"] for x in edges})
                self.assertEqual(skipped["no_evidence"], 1)

    def test_8b_a_register_built_before_the_ip_was_recorded_degrades_openly(self):
        r = full(1)
        del geo_entry(r)["metadata"]["ip"]                                                    # an older register
        g = eg.build_entity_graph(r)
        self.assertNotIn("originated at", {e["rel"] for e in g["edges"]})
        self.assertEqual(g["status"], "ok")
        self.assertIn("left out", eg.status_message(g)[1])

    def test_9_geoip_evidence_with_the_wrong_source_provenance_type_reference_or_status_is_rejected(self):
        cases = [("source", s) for s in ("llm", "tor_check", "geolocate / tor_check", "Geolocate", "", None)]
        cases += [("origin", s) for s in ("direct_machine", "historical", "untrusted_claim", "trusted_external", "llm", None, "")]
        cases += [("type", s) for s in ("URL", "header", "geoip", "", None)]
        cases += [("source_reference", s) for s in ("result.geo", "result.geo.origin ", "result.geo.origin.ip", "result.iocs.ips", None)]
        cases += [("status", s) for s in ("failed", "missing", "error", "", None)]
        for key, value in cases:
            with self.subTest(**{key: value}):
                r = full(1)
                geo_entry(r)[key] = value
                self.assertNotIn("originated at", rels_of(r))

    def test_9b_the_builder_records_the_origin_ip_as_structured_metadata_without_changing_the_rest(self):
        e = geo_entry(full(1))
        self.assertEqual(e["metadata"]["ip"], "8.8.4.4")
        self.assertEqual({k: e["metadata"][k] for k in ("approximate", "country", "source")}, {"approximate": True, "country": "Germany", "source": "test"})
        self.assertRegex(e["observation"], r"^Origin IP 8\.8\.4\.4: country=Germany, ASN=AS1, infra=hosting \(source: test; approximate\)$")
        self.assertEqual((e["type"], e["source"], e["origin"], e["status"], e["source_reference"]), ("GeoIP", "geolocate", "inference", "ok", "result.geo.origin"))
        r = full(1)
        r["geo"]["origin"]["country"] = "Unknown"
        e = geo_entry(rebuild(r))
        self.assertEqual((e["status"], e["metadata"]["ip"]), ("partial", "8.8.4.4"))
        for origin in ({}, "x"):                                                              # no IP / malformed: nothing to record
            r = full(1)
            r["geo"]["origin"] = origin
            e = next(x for x in rebuild(r)["evidence_register"] if x["type"] == "GeoIP")
            self.assertIn(e["status"], ("missing", "failed"))
            self.assertNotIn("ip", e.get("metadata") or {})

    # ---- 10-11: missing/failed evidence, persistence ----------------------------------------------------------------
    def test_10_missing_or_failed_evidence_produces_no_unsupported_edge(self):
        r = full(1)
        r["evidence_register"] = [e for e in r["evidence_register"] if e["type"] != "GeoIP"]
        self.assertNotIn("originated at", rels_of(r))
        r = full(1)
        r["evidence_register"] = [e for e in r["evidence_register"] if not (isinstance(e.get("metadata"), dict) and e["metadata"].get("claim"))]
        self.assertFalse(rels_of(r) & {"sent by", "at domain", "from domain", "replies to", "return path"})
        r = with_urls(1, [url_item("real.example")])
        r["evidence_register"] = [e for e in r["evidence_register"] if e["type"] != "URL"]
        self.assertFalse(rels_of(r) & {"links to", "at host"})
        r = with_urls(1, [url_item("real.example")])
        for e in r["evidence_register"]:
            if e["type"] in ("URL", "GeoIP") or (isinstance(e.get("metadata"), dict) and e["metadata"].get("claim")):
                e["status"] = "failed"
        edges, skipped = derived(r)
        self.assertFalse({x["rel"] for x in edges} & {"links to", "at host", "originated at", "sent by", "at domain", "from domain", "replies to", "return path"})
        self.assertGreaterEqual(skipped["no_evidence"], 8)
        self.assert_only_allowed_provenance(r, edges)

    def test_10b_property_no_edge_ever_cites_evidence_outside_the_allowed_provenance(self):
        r0 = with_urls(2, [url_item("real.example"), url_item("other.example", "/x")])
        self.assertTrue(derived(r0)[0])
        for i in range(len(r0["evidence_register"])):
            for origin in ("llm", "trusted_external", None, "inference", "historical", "untrusted_claim", "direct_machine"):
                r = copy.deepcopy(r0)
                r["evidence_register"][i]["origin"] = origin
                self.assert_only_allowed_provenance(r, derived(r)[0])
            for source in ("llm", "tor_check", None):
                r = copy.deepcopy(r0)
                r["evidence_register"][i]["source"] = source
                self.assert_only_allowed_provenance(r, derived(r)[0])

    def test_11_unsupported_edges_are_never_persisted(self):
        def stored_rels():
            conn = sqlite3.connect(self.db)
            try:
                return {row[0] for row in conn.execute("SELECT DISTINCT rel FROM entity_edges")}
            finally:
                conn.close()
        cases = []
        r = full(1)
        geo_entry(r)["metadata"]["ip"] = "1.1.1.1"
        cases.append((r, {"originated at"}, ("8.8.4.4", "1.1.1.1")))
        r = with_urls(1, [url_item("onlyurl.example")])
        per_item(r)["result.iocs.urls[0]"]["origin"] = "llm"
        cases.append((r, {"links to", "at host"}, ("onlyurl.example", TOKEN)))
        r = full(1)
        claim_entries(r)["reply_to_domain"]["origin"] = "direct_machine"
        cases.append((r, {"replies to"}, ()))
        r = full(1)
        del geo_entry(r)["metadata"]["ip"]
        cases.append((r, {"originated at"}, ("8.8.4.4",)))
        for r, banned, texts in cases:
            with self.subTest(sorted(banned)):
                self.db = _tmp_db(self)
                g = eg.build_entity_graph(r)
                self.assertEqual(g["status"], "ok")
                self.assertFalse(stored_rels() & banned)
                self.assertFalse({e["rel"] for e in g["edges"]} & banned)
                self.assertEqual(len(entity_rows(self.db)[0]), len(g["edges"]))              # exactly what was derived, nothing extra
                for text in texts:
                    self.assertNotIn(text, repr(entity_rows(self.db)) + repr(g))
                self.assertGreater(g["skipped"]["no_evidence"], 0)

    def test_11b_an_edge_that_loses_its_support_is_removed_from_storage_on_reprocessing(self):
        eg.build_entity_graph(full(1))
        conn = sqlite3.connect(self.db)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM entity_edges WHERE rel = 'originated at'").fetchone()[0], 1)
        conn.close()
        r = full(1)
        geo_entry(r)["metadata"]["ip"] = "1.1.1.1"
        g = eg.build_entity_graph(r)
        self.assertEqual(g["status"], "ok")
        conn = sqlite3.connect(self.db)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM entity_edges WHERE rel = 'originated at'").fetchone()[0], 0)
        conn.close()

    # ---- 12: explanations and status handling stay correct ---------------------------------------------------------
    def test_12_explanations_and_status_handling_are_unchanged_for_supported_and_unsupported_graphs(self):
        eg.build_entity_graph(full(1))
        r = full(2)
        g = eg.build_entity_graph(r)
        self.assertEqual(g["status"], "ok")
        self.assertEqual(eg.status_message(g), ("ok", ""))
        by = {e["rel"]: e for e in g["edges"]}
        self.assertTrue(by["originated at"]["explanation"].startswith("Inferred (approximate), not directly observed:"))
        self.assertIn("geolocate:inference", by["originated at"]["explanation"])
        self.assertTrue(by["replies to"]["explanation"].startswith("Observed in this scan:"))
        self.assertIn("email_parser:untrusted_claim", by["replies to"]["explanation"])
        self.assertIn("ioc_extract:direct_machine", by["links to"]["explanation"])
        for e in g["edges"]:
            self.assertIn(", ".join(e["evidence"]), e["explanation"])
        self.assertIn("not confirmed common authorship", by["similar tactics to"]["explanation"])
        # partly unsupported: still ok, and the user is told
        r2 = full(3)
        geo_entry(r2)["origin"] = "direct_machine"
        g2 = eg.build_entity_graph(r2)
        self.assertEqual(g2["status"], "ok")
        self.assertIn("left out", eg.status_message(g2)[1])
        # nothing supported at all: never reported as a clean result
        r3 = valid_but_empty(4)
        r3["parsed"] = {"from_addr": SENDER, "from_domain": "evil.example"}
        r3["evidence_register"] = [e for e in r3["evidence_register"] if not (isinstance(e.get("metadata"), dict) and e["metadata"].get("claim"))]
        g3 = eg.build_entity_graph(r3)
        self.assertEqual((g3["status"], g3["reason"]), ("insufficient_evidence", "relationships_unsupported"))
        self.assertIn("not a clean result", eg.status_message(g3)[1])
        # evidence-generation failure keeps its own status
        r4 = full(5)
        r4["evidence_error"] = "RuntimeError"
        self.assertEqual(eg.build_entity_graph(r4)["reason"], "evidence_unavailable")


# ---------------------------------------------------------------------------------------------------------------------
# URL normalisation hardening: ports, IPv6 literals, correctly typed host entities, privacy
# ---------------------------------------------------------------------------------------------------------------------
KEY = b"k" * 32


def n_url(url):
    return eg._e_norm("url", url)


def ext_item(url, flagged=True):
    """A URL item as ioc_extract produces it: 'host' is urlparse(url).hostname.lower() (no brackets, IPv6 as typed)."""
    from urllib.parse import urlparse
    host = (urlparse(url).hostname or "").lower()
    return {"url": url, "host": host, "suspicious": flagged, "risk": 0.9 if flagged else 0.0,
            "flags": ["URL shortener hides the real destination"] if flagged else []}


def host_edge(edges):
    return next(e for e in edges if e["rel"] == "at host")


def readable_text(path):
    """Every human-readable column of the stored edges (never the hex ids, which contain arbitrary short fragments by chance)."""
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute("SELECT src_label, dst_label, evidence_note, provenance, detail, ref, rel FROM entity_edges").fetchall()
    finally:
        conn.close()
    return " | ".join(str(v) for row in rows for v in row if v is not None)


class UrlNormalizationPorts(unittest.TestCase):
    def test_different_non_default_ports_are_different_identities(self):
        a, b = n_url("http://evil.example:8080/path"), n_url("http://evil.example:9090/path")
        self.assertEqual((a, b), ("http://evil.example:8080/path", "http://evil.example:9090/path"))
        self.assertNotEqual(eg._e_id(KEY, "url", a), eg._e_id(KEY, "url", b))
        self.assertNotEqual(n_url("http://evil.example:8080/p"), n_url("http://evil.example/p"))
        self.assertEqual(eg._e_label("url", a), eg._e_label("url", b))                  # the readable label is still just the host

    def test_explicit_default_ports_normalize_like_no_port(self):
        self.assertEqual(n_url("http://evil.example:80/p"), n_url("http://evil.example/p"))
        self.assertEqual(n_url("https://evil.example:443/p"), n_url("https://evil.example/p"))
        self.assertEqual(n_url("HTTP://EVIL.example.:80/p?q=1#f"), "http://evil.example/p")
        self.assertEqual(eg._e_id(KEY, "url", n_url("http://evil.example:80/p")), eg._e_id(KEY, "url", n_url("http://evil.example/p")))

    def test_a_default_port_of_the_other_scheme_is_a_distinct_endpoint(self):
        self.assertEqual(n_url("http://evil.example:443/p"), "http://evil.example:443/p")
        self.assertEqual(n_url("https://evil.example:80/p"), "https://evil.example:80/p")
        self.assertNotEqual(n_url("http://evil.example:443/p"), n_url("http://evil.example/p"))

    def test_invalid_ports_are_rejected_safely(self):
        for port in ("abc", "-1", "+80", "65536", "99999", "100000", "0", "00000", "8080x", "80 80", "0x50", "8.0", "\uff18\uff10",
                     "\u0668\u0660", "1" * 400):
            with self.subTest(port=port):
                self.assertIsNone(n_url("http://evil.example:%s/p" % port))

    def test_port_boundaries_leading_zeros_and_empty_port(self):
        self.assertEqual(n_url("http://evil.example:1/p"), "http://evil.example:1/p")
        self.assertEqual(n_url("http://evil.example:65535/p"), "http://evil.example:65535/p")
        self.assertEqual(n_url("http://evil.example:08080/p"), n_url("http://evil.example:8080/p"))
        self.assertEqual(n_url("http://evil.example:/p"), n_url("http://evil.example/p"))      # empty port = the scheme default


class UrlNormalizationIPv6(unittest.TestCase):
    def test_valid_ipv6_url_normalizes_exactly_as_specified(self):
        self.assertEqual(n_url("https://[2606:4700:4700::1111]:8443/path?token=secret"), "https://[2606:4700:4700::1111]:8443/path")
        self.assertEqual(n_url("https://[2606:4700:4700::1111]/"), "https://[2606:4700:4700::1111]/")
        self.assertEqual(n_url("http://[2606:4700:4700::1111]"), "http://[2606:4700:4700::1111]/")

    def test_ipv6_is_canonically_compressed_and_lowercased(self):
        want = "https://[2606:4700:4700::1111]/p"
        for spelling in ("2606:4700:4700:0:0:0:0:1111", "2606:4700:4700:0000:0000:0000:0000:1111", "2606:4700:4700::1111",
                         "2606:4700:4700:0::1111", "2606:4700:4700::0:1111", "2606:4700:4700::1111".upper()):
            with self.subTest(spelling=spelling):
                self.assertEqual(n_url("https://[%s]/p" % spelling), want)
        self.assertEqual(n_url("https://[2001:4860:4860::8888]/p"), "https://[2001:4860:4860::8888]/p")

    def test_ipv6_with_default_and_non_default_ports(self):
        self.assertEqual(n_url("https://[2606:4700:4700::1111]:443/p"), "https://[2606:4700:4700::1111]/p")
        self.assertEqual(n_url("http://[2606:4700:4700::1111]:80/p"), "http://[2606:4700:4700::1111]/p")
        self.assertEqual(n_url("http://[2606:4700:4700::1111]:8080/p"), "http://[2606:4700:4700::1111]:8080/p")
        self.assertNotEqual(n_url("http://[2606:4700:4700::1111]:8080/p"), n_url("http://[2606:4700:4700::1111]:9090/p"))
        for bad in ("0", "65536", "abc", "-1"):
            self.assertIsNone(n_url("http://[2606:4700:4700::1111]:%s/p" % bad))

    def test_the_complete_ipv6_address_is_the_host_label(self):
        for url in ("https://[2606:4700:4700::1111]:8443/path?token=secret", "http://[2606:4700:4700:0:0:0:0:1111]/p"):
            self.assertEqual(eg._e_label("url", n_url(url)), "2606:4700:4700::1111")           # not "2606", not bracketed, not a prefix
        self.assertEqual(eg._e_norm("ip", "2606:4700:4700::1111"), "2606:4700:4700::1111")
        self.assertEqual(eg._e_host_type("2606:4700:4700::1111"), "ip")

    def test_malformed_ipv6_is_rejected(self):
        for bad in ("http://[2606:4700:4700::1111/path", "http://2606:4700:4700::1111]/path", "http://[2606:4700:4700::zzzz]/",
                    "http://[]/", "http://[::1]x/", "http://[2606:4700:4700::1111]junk", "http://[2606:4700:4700::1111]:99999/",
                    "http://[1.2.3.4]/", "http://[2606:4700:4700::1111::1]/", "http://[2606:4700:4700:1:2:3:4:5:6]/",
                    "http://[12345::1]/", "http://[[2606:4700:4700::1111]]/", "https://[2606:4700:4700::1111",
                    "http://[2606:4700:4700::1111]:80:80/"):
            with self.subTest(bad=bad):
                self.assertIsNone(n_url(bad))

    def test_scoped_ipv6_is_rejected_everywhere(self):
        for bad in ("http://[fe80::1%25eth0]/", "http://[fe80::1%eth0]/", "http://[2606:4700:4700::1111%25eth0]/",
                    "http://[2606:4700:4700::1111%eth0]:80/p", "http://[2606:4700:4700::1111%]/", "http://[2606:4700:4700::1111%0]/"):
            with self.subTest(bad=bad):
                self.assertIsNone(n_url(bad))
        self.assertIsNone(eg._e_norm("ip", "2606:4700:4700::1111%eth0"))                    # ipaddress would accept this one
        self.assertIsNone(eg._e_norm("ip", "fe80::1%eth0"))

    def test_unbracketed_ipv6_is_never_read_as_a_host_and_port(self):
        for bad in ("http://2606:4700:4700::1111/path", "http://2606:4700:4700::1111:8080/path", "http://::1/", "https://2606:4700/"):
            with self.subTest(bad=bad):
                self.assertIsNone(n_url(bad))

    def test_non_global_ips_keep_being_rejected(self):
        for bad in ("http://[::1]/", "http://[::]/", "http://[fd00::1]/", "http://[fe80::1]/", "http://[2001:db8::1]/", "http://[ff02::1]/",
                    "http://127.0.0.1/", "http://127.0.0.1:8080/", "http://10.0.0.1/", "http://192.168.1.1/", "http://172.16.0.1/",
                    "http://169.254.169.254/latest", "http://0.0.0.0/", "http://100.64.0.1/", "http://255.255.255.255/",
                    "http://224.0.0.1/", "http://239.255.255.250/", "http://[ff02::1]:8443/", "http://[ff0e::1]/"):
            with self.subTest(bad=bad):
                self.assertIsNone(n_url(bad))


class UrlNormalizationHostTypes(Base):
    def edges_for(self, *urls, n=1):
        r = with_urls(n, [ext_item(u) for u in urls])
        return eg.derive_entity_edges(r, KEY)

    def test_ipv4_url_host_is_an_ip_node_not_a_domain(self):
        edges, skipped = self.edges_for("http://8.8.4.44:8080/x")
        h = host_edge(edges)
        self.assertEqual((h["dst"]["type"], h["dst"]["label"], h["src"]["type"]), ("ip", "8.8.4.44", "url"))
        self.assertTrue(h["dst"]["id"].startswith("ip:"))
        self.assertFalse([e for e in edges if e["dst"]["type"] == "domain" and e["dst"]["label"] == "8.8.4.44"])
        self.assertEqual(skipped["no_evidence"], 0)

    def test_ipv6_url_host_is_an_ip_node(self):
        edges, _ = self.edges_for("https://[2606:4700:4700::1111]:8443/path?token=secret")
        h = host_edge(edges)
        self.assertEqual((h["dst"]["type"], h["dst"]["label"]), ("ip", "2606:4700:4700::1111"))
        self.assertEqual(next(e for e in edges if e["rel"] == "links to")["dst"]["label"], "2606:4700:4700::1111")

    def test_dns_url_host_is_a_domain_node(self):
        edges, _ = self.edges_for("http://evil.example:8080/x")
        h = host_edge(edges)
        self.assertEqual((h["dst"]["type"], h["dst"]["label"]), ("domain", "evil.example"))

    def test_an_ip_literal_is_never_a_domain_even_when_its_parts_fit_the_domain_pattern(self):
        for lit in ("8.8.4.44", "1.2.3.45", "8.8.8.88", "0x7f.0x0.0x0.0x1", "2130706433", "127.1", "1.2.3", "010.001.001.100"):
            with self.subTest(lit=lit):
                self.assertIsNone(eg._e_norm("domain", lit))                                   # never a domain node, however it is spelled
        for lit in ("0x7f.0x0.0x0.0x1", "2130706433", "127.1", "1.2.3", "010.001.001.100"):
            with self.subTest(url_lit=lit):
                self.assertIsNone(n_url("http://%s/p" % lit))                                   # and obfuscated forms are not URL hosts either
        for lit in ("8.8.4.44", "1.2.3.45", "8.8.8.88"):
            with self.subTest(global_ipv4=lit):
                self.assertEqual(n_url("http://%s:8080/p" % lit), "http://%s:8080/p" % lit)     # a genuine IPv4 host stays usable ...
                self.assertEqual(eg._e_host_type(lit), "ip")                                    # ... as an IP
        self.assertEqual(eg._e_norm("domain", "8.8.4.44.example.com"), "8.8.4.44.example.com")        # a real DNS name still is one
        self.assertEqual(eg._e_host_type("evil.example"), "domain")

    def test_host_typing_does_not_depend_on_the_domain_pattern_rejecting_ip_literals(self):
        with mock.patch.object(eg, "_E_NUMERIC_TLD_RE", re.compile(r"(?!)")):                   # simulate the domain guard failing open
            self.assertEqual(eg._e_norm("domain", "8.8.4.44"), "8.8.4.44")                      # (the guard really is disabled here)
            edges, _ = self.edges_for("http://8.8.4.44:8080/x")
            h = host_edge(edges)
            self.assertEqual((h["dst"]["type"], h["dst"]["label"]), ("ip", "8.8.4.44"))        # typing by parsing still yields an ip node

    def test_private_and_obfuscated_ip_urls_create_no_url_or_host_entity_and_persist_nothing(self):
        bad = ("http://10.0.0.1/x", "http://127.0.0.1:8080/x", "http://192.168.1.1/", "http://169.254.169.254/latest",
               "http://[::1]/", "http://[fd00::1]:8443/x", "http://0x7f.0x0.0x0.0x1/", "http://2130706433/", "http://017700000001/")
        for url in bad:
            with self.subTest(url=url):
                self.db = _tmp_db(self)
                g = eg.build_entity_graph(with_urls(1, [ext_item(url)]))
                self.assertFalse([e for e in g["edges"] if e["rel"] in ("links to", "at host")])
                self.assertGreater(g["skipped"]["invalid_entity"], 0)
                self.assertFalse(sqlite3.connect(self.db).execute("SELECT COUNT(*) FROM entity_edges WHERE src_type='url' OR dst_type='url'").fetchone()[0])
                shown = readable_text(self.db)
                for text in ("10.0.0.1", "127.0.0.1", "192.168.1.1", "169.254", "fd00", "0x7f", "2130706433", "017700000001", "::1"):
                    self.assertNotIn(text, shown)

    def test_existing_domain_correlation_still_works_with_ports_and_case(self):
        r = with_urls(1, [ext_item("http://EVIL.example.:8080/x")])
        edges, _ = eg.derive_entity_edges(r, KEY)
        from_dom = next(e for e in edges if e["rel"] == "from domain")["dst"]
        self.assertEqual(host_edge(edges)["dst"]["id"], from_dom["id"])                     # one domain entity for From and for the URL host
        self.assertEqual(from_dom["id"], eg._e_id(KEY, "domain", "evil.example"))

    def test_two_ports_two_url_entities_one_host_each_citing_its_own_evidence(self):
        r = with_urls(1, [ext_item("http://port.example:8080/p"), ext_item("http://port.example:9090/p")])
        items = per_item(r)
        edges, skipped = eg.derive_entity_edges(r, KEY)
        links = [e for e in edges if e["rel"] == "links to"]
        hosts = [e for e in edges if e["rel"] == "at host"]
        self.assertEqual(len({e["dst"]["id"] for e in links}), 2)
        self.assertEqual(len({e["dst"]["id"] for e in hosts}), 1)
        self.assertEqual(sorted(tuple(e["evidence"]) for e in links), sorted((items["result.iocs.urls[%d]" % i]["id"],) for i in range(2)))
        self.assertEqual(skipped["no_evidence"], 0)

    def test_an_explicit_default_port_and_no_port_are_one_entity(self):
        r = with_urls(1, [ext_item("http://same.example:80/p"), ext_item("http://same.example/p")])
        edges, skipped = eg.derive_entity_edges(r, KEY)
        self.assertEqual(len([e for e in edges if e["rel"] == "links to"]), 1)
        self.assertEqual(skipped["no_evidence"], 0)

    def test_per_item_evidence_matches_ipv6_in_any_spelling_and_rejects_another_address(self):
        url = "https://[2606:4700:4700:0:0:0:0:1111]:8443/path"
        r = with_urls(1, [ext_item(url)])
        self.assertEqual(per_item(r)["result.iocs.urls[0]"]["metadata"]["host"], "2606:4700:4700:0:0:0:0:1111")   # as the extractor records it
        self.assertTrue({"links to", "at host"} <= {e["rel"] for e in eg.derive_entity_edges(r, KEY)[0]})
        for spelling in ("[2606:4700:4700::1111]", "2606:4700:4700::1111", "2606:4700:4700:0000:0000:0000:0000:1111"):
            with self.subTest(spelling=spelling):
                per_item(r)["result.iocs.urls[0]"]["metadata"]["host"] = spelling
                self.assertTrue({"links to", "at host"} <= {e["rel"] for e in eg.derive_entity_edges(r, KEY)[0]})
        for other in ("2606:4700:4700::1112", "2606:4700::1111", "1.1.1.1", "", "[]", "fe80::1%eth0"):
            with self.subTest(other=other):
                per_item(r)["result.iocs.urls[0]"]["metadata"]["host"] = other
                self.assertFalse({"links to", "at host"} & {e["rel"] for e in eg.derive_entity_edges(r, KEY)[0]})

    def test_the_extractors_truncated_ipv6_url_is_rejected_safely(self):
        item = {"url": "https://[2606:4700:4700::1111", "host": "", "suspicious": True, "risk": 0.9, "flags": ["x"]}   # what ioc_extract yields today
        edges, skipped = eg.derive_entity_edges(with_urls(1, [item]), KEY)
        self.assertFalse([e for e in edges if e["rel"] in ("links to", "at host")])
        self.assertGreater(skipped["invalid_entity"], 0)

    def test_hostile_and_malformed_input_never_raises(self):
        weird = ["http://[", "http://]", "http://@", "http://:80", "http://[::1]:abc", "http://a b.example/", "http://evil.example\x00/", "http://\u202eevil.example/",
                 "http://\u00e9vil.example/", "http://evil.example\\@good.example/", "http:///path", "http://./", "http://-.example/", "http://" + "a" * 300 + ".example/",
                 "http://" + ".".join(["a"] * 200) + "/", "http://evil.example:80:80/", "http://user:pass@", "http://@@@evil.example/", "HTTP:evil.example", "//evil.example/",
                 "http://[2606:4700:4700::1111]:\x00/", "\u0000", "http://evil.example/\n", " http://evil.example/ ", "http://%65vil.example/", "http://evil..example/", "http://evil.example..", "http://.evil.example/"]
        for url in weird:
            with self.subTest(url=url[:40]):
                out = n_url(url)
                self.assertTrue(out is None or (isinstance(out, str) and out.startswith(("http://", "https://"))))
        for junk in (None, 5, b"http://evil.example/", [], {}, "", " ", "x" * 5000):
            self.assertIsNone(n_url(junk))

    def test_plain_urls_keep_their_existing_behaviour(self):
        self.assertEqual(n_url("http://evil.example/p?x=1"), "http://evil.example/p")
        self.assertEqual(n_url("HTTP://EVIL.Example./P"), "http://evil.example/P")            # scheme and host are case-folded, the path is not
        self.assertEqual(n_url("http://evil.example"), "http://evil.example/")
        self.assertEqual(n_url("https://sub.evil.example/a/b;c=d"), "https://sub.evil.example/a/b;c=d")
        for bad in ("ftp://x.example/a", "javascript:alert(1)", "http://", "mailto:a@b.example", "file:///etc/passwd", "data:text/html,x"):
            self.assertIsNone(n_url(bad))


class UrlNormalizationPrivacy(Base):
    def persisted_and_returned(self, g):
        conn = sqlite3.connect(self.db)
        try:
            cols = conn.execute("SELECT src_label, dst_label, evidence_note, provenance, detail, ref FROM entity_edges").fetchall()
        finally:
            conn.close()
        return repr(entity_rows(self.db)) + repr(g), cols

    def test_userinfo_path_query_fragment_and_tokens_are_never_persisted_or_returned(self):
        url = "https://user:pa55word@priv.example:8443/secret/seg?token=tok3n&k=v#frag"
        g = eg.build_entity_graph(with_urls(1, [ext_item(url)]))
        self.assertTrue([e for e in g["edges"] if e["rel"] == "links to"])
        blob, cols = self.persisted_and_returned(g)
        for text in ("pa55word", "user:", "user@", "secret", "seg", "tok3n", "frag", "token=", "k=v", "https://", "http://", "priv.example:", "/secret"):
            self.assertNotIn(text, blob)
        self.assertEqual(eg._e_label("url", eg._e_norm("url", url)), "priv.example")
        self.assertIn("priv.example", blob)                                                       # the approved host label IS stored

    def test_credentials_cannot_spoof_the_host(self):
        g = eg.build_entity_graph(with_urls(1, [ext_item("http://decoyname.example:pw@realhost.example:8080/p")]))
        blob, _ = self.persisted_and_returned(g)
        self.assertIn("realhost.example", blob)
        self.assertNotIn("decoyname", blob)
        self.assertEqual(eg._e_label("url", n_url("http://decoyname.example@realhost.example/p")), "realhost.example")
        self.assertEqual(n_url("http://realhost.example@decoyname.example/p"), "http://decoyname.example/p")

    def test_ipv6_url_with_port_path_and_token_persists_only_the_address(self):
        url = "https://[2606:4700:4700::1111]:8443/very/private/path?token=sekret#frag"
        g = eg.build_entity_graph(with_urls(1, [ext_item(url)]))
        self.assertTrue([e for e in g["edges"] if e["rel"] == "at host" and e["dst"]["type"] == "ip"])
        blob, cols = self.persisted_and_returned(g)
        for text in ("very/private", "sekret", "frag", "token=", "https://", "[2606", "8443"):
            self.assertNotIn(text, readable_text(self.db) + repr(g))                              # nothing but the bare address is readable
        self.assertNotIn("sekret", blob)
        self.assertNotIn("very/private", blob)
        self.assertIn("2606:4700:4700::1111", blob)

    def test_every_readable_column_holds_only_approved_values(self):
        urls = ["http://user:pw@a.example:8080/p/q?t=1#f", "https://[2606:4700:4700::1111]:8443/p?t=1", "http://8.8.4.44:81/z?s=3"]
        g = eg.build_entity_graph(with_urls(1, [ext_item(u) for u in urls]))
        conn = sqlite3.connect(self.db)
        try:
            labels = {v for row in conn.execute("SELECT src_label, dst_label FROM entity_edges") for v in row if v is not None}
        finally:
            conn.close()
        allowed = re.compile(r"^(SC-[0-9a-f]{32}|[a-z0-9._-]+\.[a-z0-9-]+|[0-9a-f:.]+)$")
        for label in labels:
            self.assertRegex(label, allowed)
            for banned in ("/", "?", "#", "@", "=", "pw", "user", "http"):
                self.assertNotIn(banned, label)
        self.assertTrue({"a.example", "2606:4700:4700::1111", "8.8.4.44"} <= labels)

    def test_the_hmac_identity_still_distinguishes_urls_without_exposing_them(self):
        r = with_urls(1, [ext_item("http://priv.example:8080/one?t=1"), ext_item("http://priv.example:8080/two?t=1")])
        edges, _ = eg.derive_entity_edges(r, KEY)
        ids = [e["dst"]["id"] for e in edges if e["rel"] == "links to"]
        self.assertEqual(len(set(ids)), 2)
        for i in ids:
            self.assertRegex(i, r"^url:[0-9a-f]{32}$")
        other_key = eg.derive_entity_edges(r, b"z" * 32)[0]
        self.assertNotEqual(ids, [e["dst"]["id"] for e in other_key if e["rel"] == "links to"])      # keyed: different session, different ids


# ---------------------------------------------------------------------------------------------------------------------
# Browser/parser hostname disagreement and malformed Unicode
# ---------------------------------------------------------------------------------------------------------------------
BACKSLASH_URL = r"http://evil.example\@good.example/login"       # a browser goes to evil.example; urlparse()/urlsplit() say good.example
PERCENT_URL = r"http://evil.example%5C@good.example/login"       # %5C is ordinary text: every parser says good.example


class UrlParserDisagreement(Base):
    def test_a_raw_backslash_in_the_authority_is_rejected_by_url_normalisation(self):
        for url in (BACKSLASH_URL, r"https://evil.example\@good.example/", r"http://evil.example\good.example/", r"http://\evil.example/",
                    r"HTTP://EVIL.example\@good.example/x", r"http://u:p@evil.example\@good.example:8080/p",
                    r"http://evil.example\@[2606:4700:4700::1111]/x", r"http://good.example\@evil.example"):
            with self.subTest(url=url):
                self.assertIsNone(n_url(url))

    def test_percent_encoded_5c_is_not_treated_as_a_backslash(self):
        self.assertEqual(n_url(PERCENT_URL), "http://good.example/login")                  # control: agreed host, no over-blocking
        self.assertEqual(n_url(r"http://evil.example%5c@good.example/login"), "http://good.example/login")
        self.assertEqual(n_url(r"http://good.example/a\b"), r"http://good.example/a\b")     # a backslash in the PATH does not move the host

    def test_the_example_cannot_create_a_good_example_relationship_from_any_extractor_output(self):
        valid = ext_item("http://valid.example/login")
        pre_fix = {"url": BACKSLASH_URL, "host": "good.example", "suspicious": True, "risk": 0.5,      # what the old extractor recorded
                   "flags": ["Path suggests a credential-entry page"]}
        current = ioc.extract({"body_text": "Click " + BACKSLASH_URL + " now", "html_body": "", "headers": {}})["urls"][0]
        self.assertEqual(current["host"], "")                                                  # the extractor no longer invents a host
        for label, bad in (("pre-fix extractor output", pre_fix), ("current extractor output", current)):
            with self.subTest(label):
                r = with_urls(1, [bad, valid])
                edges, skipped = eg.derive_entity_edges(r, KEY)
                names = {e["src"]["label"] for e in edges} | {e["dst"]["label"] for e in edges}
                self.assertNotIn("good.example", names)
                self.assertEqual([e["dst"]["label"] for e in edges if e["rel"] == "at host"], ["valid.example"])
                self.assertEqual(len([e for e in edges if e["rel"] == "links to"]), 1)        # only the valid URL
                self.assertGreater(skipped["invalid_entity"], 0)
                self.db = _tmp_db(self)
                g = eg.build_entity_graph(r)
                self.assertEqual(g["status"], "ok")
                self.assertNotIn("good.example", readable_text(self.db) + repr(g))

    def test_the_percent_encoded_control_still_reaches_the_host_both_parsers_agree_on(self):
        current = ioc.extract({"body_text": "Click " + PERCENT_URL + " now", "html_body": "", "headers": {}})["urls"][0]
        self.assertEqual(current["host"], "good.example")
        edges, _ = eg.derive_entity_edges(with_urls(1, [current]), KEY)
        self.assertEqual([e["dst"]["label"] for e in edges if e["rel"] == "at host"], ["good.example"])

    def test_the_ambiguity_flag_is_not_an_attack_dna_url_tactic(self):
        current = ioc.extract({"body_text": BACKSLASH_URL, "html_body": "", "headers": {}})["urls"][0]
        flag = next(f for f in current["flags"] if f.startswith("Ambiguous address"))
        self.assertIsNone(dna._url_tag(flag))                                                  # Phase 2 fingerprints are unaffected


class UrlUnicodeSafety(Base):
    def test_lone_surrogates_are_rejected_by_url_normalisation(self):
        for url in ("http://evil.example/p\ud800q", "http://evil.example/p?q=\ud800", "http://evil.example/p#\udfff",
                    "http://us\ud800er@evil.example/p", "http://evil.example/\udc00", "http://evil.example/\ud83d\ude00",
                    "\ud800http://evil.example/"):
            with self.subTest(url=ascii(url)):
                self.assertIsNone(n_url(url))

    def test_the_hmac_step_would_raise_on_a_surrogate_which_is_why_normalisation_rejects_it(self):
        with self.assertRaises(UnicodeEncodeError):
            eg._e_id(KEY, "url", "http://evil.example/\ud800")                                 # _e_id itself is deliberately unchanged

    def test_valid_non_ascii_text_is_not_over_rejected(self):
        for url in ("http://evil.example/\U0001F600", "http://evil.example/caf\u00e9?q=\u00fc"):
            with self.subTest(url=ascii(url)):
                n = n_url(url)
                self.assertTrue(n.startswith("http://evil.example/"))
                self.assertRegex(eg._e_id(KEY, "url", n), r"^url:[0-9a-f]{32}$")               # and it can be hashed

    def test_a_malformed_url_does_not_turn_the_graph_into_an_error_or_disturb_other_relationships(self):
        good = ext_item("http://valid.example/login")
        bad = ext_item("http://evil.example/p\ud800q")
        r0 = with_urls(1, [good])
        g0 = eg.build_entity_graph(r0)
        r1 = copy.deepcopy(r0)
        r1["iocs"]["urls"] = [good, bad]
        rebuild(r1)
        g1 = eg.build_entity_graph(r1)
        self.assertEqual((g0["status"], g1["status"]), ("ok", "ok"))                           # not "error"
        self.assertTrue(g1["stored"])
        sig = lambda g: sorted((e["rel"], e["src"]["id"], e["dst"]["id"]) for e in g["edges"])
        self.assertEqual(sig(g1), sig(g0))                                                     # every other relationship is identical
        self.assertTrue([e for e in g1["edges"] if e["rel"] == "at host" and e["dst"]["label"] == "valid.example"])
        self.assertGreater(g1["skipped"]["invalid_entity"], g0["skipped"]["invalid_entity"])   # the bad URL was skipped and counted
        self.assertNotIn("\ud800", readable_text(self.db))


# ---------------------------------------------------------------------------------------------------------------------
# IPv6 classification consistency between the extractor and the Entity Graph
# ---------------------------------------------------------------------------------------------------------------------
IPV6_URL = "https://[2606:4700:4700::1111]:8443/path?token=secret"
CANON6 = "2606:4700:4700::1111"


def real_extract(text):
    return ioc.extract({"body_text": text, "html_body": "", "headers": {}})


class Ipv6ClassificationConsistency(Base):
    def test_an_ipv6_url_host_becomes_an_ip_entity_end_to_end(self):
        iocs = real_extract("Open " + IPV6_URL + " now")
        self.assertEqual((iocs["ips"], iocs["domains"]), ([CANON6], []))
        edges, skipped = eg.derive_entity_edges(with_urls(1, iocs["urls"]), KEY)
        h = host_edge(edges)
        self.assertEqual((h["dst"]["type"], h["dst"]["label"]), ("ip", CANON6))
        self.assertTrue(h["dst"]["id"].startswith("ip:"))
        self.assertEqual(next(e for e in edges if e["rel"] == "links to")["dst"]["label"], CANON6)
        self.assertEqual(skipped["no_evidence"], 0)                                          # the raw-IP score makes the URL evidence-eligible
        self.assertFalse([e for e in edges if e["dst"]["type"] == "domain" and ":" in (e["dst"]["label"] or "")])
        self.assertIsNone(eg._e_norm("domain", CANON6))
        self.assertEqual(eg._e_host_type(CANON6), "ip")

    def test_equivalent_ipv6_spellings_give_one_ip_entity(self):
        spellings = ("2606:4700:4700:0:0:0:0:1111", "2606:4700:4700::1111", "2606:4700:4700:0000:0000:0000:0000:1111")
        iocs = real_extract(" ".join("https://[%s]/p%d" % (s, i) for i, s in enumerate(spellings)))
        self.assertEqual({u["host"] for u in iocs["urls"]}, {CANON6})
        edges, skipped = eg.derive_entity_edges(with_urls(1, iocs["urls"]), KEY)
        hosts = [e["dst"]["id"] for e in edges if e["rel"] == "at host"]
        self.assertEqual(len(hosts), 3)
        self.assertEqual(set(hosts), {eg._e_id(KEY, "ip", CANON6)})
        self.assertEqual(skipped["no_evidence"], 0)
        self.assertEqual(n_url("https://[2606:4700:4700:0:0:0:0:1111]/p"), n_url("https://[2606:4700:4700::1111]/p"))

    def test_scoped_ipv6_is_rejected_by_the_extractor_and_the_graph_alike(self):
        for url in ("https://[fe80::1%25eth0]/", "https://[fe80::1%eth0]/", "https://[2606:4700:4700::1111%25eth0]/x",
                    "https://[2606:4700:4700::1111%eth0]:8443/x"):
            with self.subTest(url=url):
                iocs = real_extract("see " + url + " now")
                self.assertEqual(iocs["urls"][0]["host"], "")
                self.assertEqual((iocs["ips"], iocs["domains"]), ([], []))
                self.assertIsNone(n_url(url))
                self.assertIsNone(eg._e_norm("ip", url.split("[")[1].split("]")[0]))
                edges, _ = eg.derive_entity_edges(with_urls(1, iocs["urls"]), KEY)
                self.assertFalse([e for e in edges if e["rel"] in ("links to", "at host")])

    def test_malformed_ipv6_is_rejected_by_the_extractor_and_the_graph_alike(self):
        for url in ("http://[2606:4700:4700::1111/path", "http://[2606:4700:4700::zzzz]/x", "http://[2606:4700:4700::1111::1]/x", "http://[]/x"):
            with self.subTest(url=url):
                iocs = real_extract("x " + url + " y")
                self.assertEqual((iocs["urls"][0]["host"], iocs["ips"], iocs["domains"]), ("", [], []))
                self.assertIsNone(n_url(url))

    def test_ipv4_and_dns_host_typing_and_collections_are_unchanged(self):
        iocs = real_extract("a http://8.8.4.44:8080/x b https://dns.example/login")
        self.assertEqual((iocs["ips"], iocs["domains"]), (["8.8.4.44"], ["dns.example"]))
        edges, _ = eg.derive_entity_edges(with_urls(1, iocs["urls"]), KEY)
        self.assertEqual({e["dst"]["label"]: e["dst"]["type"] for e in edges if e["rel"] == "at host"}, {"8.8.4.44": "ip", "dns.example": "domain"})

    def test_the_backslash_controls_still_hold_end_to_end(self):
        bs = real_extract("Click " + BACKSLASH_URL + " now")
        self.assertEqual((bs["urls"][0]["host"], bs["ips"], bs["domains"]), ("", [], []))
        self.assertIsNone(n_url(BACKSLASH_URL))
        control = r"http://evil.example/%5C@good.example/login"                             # %5C inside the PATH: the host is evil.example
        ctl = real_extract("Click " + control + " now")
        self.assertEqual(ctl["urls"][0]["host"], "evil.example")
        self.assertEqual(n_url(control), control)
        edges, _ = eg.derive_entity_edges(with_urls(1, ctl["urls"]), KEY)
        self.assertEqual([e["dst"]["label"] for e in edges if e["rel"] == "at host"], ["evil.example"])
        self.assertNotIn("good.example", {e["dst"]["label"] for e in edges} | {e["src"]["label"] for e in edges})

    def test_surrogate_rejection_is_preserved(self):
        self.assertIsNone(n_url("https://[2606:4700:4700::1111]/p\ud800q"))
        self.assertIsNone(n_url("http://evil.example/p\ud800q"))


class ProtectedAndCompatibility(unittest.TestCase):
    def test_correlate_and_retro_hunt_do_not_reference_the_new_module(self):
        base = os.path.dirname(os.path.abspath(__file__))
        for name in ("correlate.py", "retro_hunt.py", "risk.py", "attack_dna.py", "classifier.py", "tracker.py"):
            with open(os.path.join(base, name), encoding="utf-8") as f:
                self.assertNotIn("entity_graph", f.read(), name)

    def test_entity_graph_does_not_touch_feedback_or_training_tables(self):
        base = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(base, "entity_graph.py"), encoding="utf-8") as f:
            src = f.read()
        for banned in ("feedback", "classifier", "contribution", "shared_indicators", "origin_embeddings", "nomic_embed", "get_connection(shared=True"):
            self.assertNotIn(banned, src)


if __name__ == "__main__":
    unittest.main()
