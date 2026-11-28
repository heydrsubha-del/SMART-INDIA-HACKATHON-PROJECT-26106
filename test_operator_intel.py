"""Phase 5 tests: operator_intel.py (impossible journey, common-operator patterns, cross-campaign correlation) and its integration
with the evidence register, analyzer, report and UI. Offline; every test that touches storage uses an isolated temporary database."""
import contextlib
import copy
import json
import os
import re
import sqlite3
import sys
import tempfile
import threading
import types
import unittest
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from unittest import mock
from urllib.parse import urlparse

import analyzer
import attack_dna as dna
import campaign_intel as ci
import entity_graph as eg
import investigation_agent as ia
import operator_intel as op
import report
import tor_check
import tracker
from test_attack_dna import mk_result, _tmp_db


def sid(n):
    return "SC-%032x" % n


# ---------------------------------------------------------------------------------------------------------------- fixtures
FRANKFURT = (50.11, 8.68)
SYDNEY = (-33.87, 151.21)
PARIS = (48.86, 2.35)
T10 = "2026-11-20T10:00:00+00:00"


def ev(n, lat=FRANKFURT[0], lon=FRANKFURT[1], when=T10, **kw):
    """A stored/extracted origin observation, as extract_event()/_load_events() produce it."""
    e = {"scan_id": sid(n), "ip": None, "ip_id": "ip:%032x" % n, "lat": lat, "lon": lon, "country": "Germany", "country_code": "DE",
         "city": "Frankfurt", "asn": "AS64500 ExampleNet", "infra": "unknown", "event_time": when, "time_reliable": True,
         "time_note": "stamped by the receiving server with an explicit time zone", "attributable": True, "attribution": [],
         "origin_confidence": 70, "evidence": {"geo": "S%d" % (10 + n), "origin": "S%d" % (20 + n), "time": "S%d" % (30 + n)}}
    e.update(kw)
    return e


def scan(n, ip="8.8.4.4", lat=FRANKFURT[0], lon=FRANKFURT[1], when="Fri, 20 Nov 2026 10:00:00 +0000", city="Frankfurt", country="Germany",
         cc="DE", asn="AS64500 ExampleNet", isp="ExampleNet", infra="unknown", protocol="ESMTPSA", confidence=70, originating=False,
         domain=None, reply_domain=None, return_domain=None, url=None, anomalies=(("high", "SPF fail"), ("high", "DKIM fail")),
         url_flags=(("URL shortener hides the real destination",),), ts_flags=(), with_origin=True, subject="Invoice", selected=None):
    """A scan result as analyzer.analyze_email() hands it over, before the register is built."""
    dom = domain or "d%d.example" % n
    r = mk_result(sid(n), from_domain=dom, reply_domain=reply_domain or "r%d.example" % n, return_domain=return_domain or "b%d.example" % n,
                  anomalies=anomalies,
                  url_flags=url_flags, infra=infra, country=cc)
    r["parsed"].update({"from_addr": "user%d@%s" % (n, dom), "subject": subject})
    link = url or "http://u%d.example/login" % n
    r["iocs"]["urls"] = [{"url": link, "host": urlparse(link).hostname, "suspicious": True, "risk": 0.8, "flags": list(url_flags[0])}]
    r["geo"]["origin"].update({"ip": ip, "lat": lat, "lon": lon, "city": city, "country": country, "country_code": cc, "asn": asn,
                               "isp": isp, "infra": infra, "source": "test"})
    if with_origin:
        ts = parsedate_to_datetime(when)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)                     # what origin_intel's route parser does with a zone-less stamp
        r["origin_intel"] = {
            "selected_ip": selected or ip, "confidence": confidence, "band": "High" if confidence >= 70 else "Medium" if confidence >= 40 else "Low",
            "flags": [], "location_disclaimer": "An IP location is where infrastructure appears to be, not where a person is.",
            "route": [{"n": 1, "from_ip": ip, "public": True, "ts": ts, "ts_text": when, "protocol": protocol, "flags": list(ts_flags),
                       "country": country, "infra": infra, "tor_exit": False, "asn": asn}],
            "corroboration": [(ip, "X-Originating-IP")] if originating else []}
    return r


def with_register(n, **kw):
    r = scan(n, **kw)
    r["evidence_register"], r["scan_findings"] = ia.build_scan_evidence(r)
    return r


def analyze(n, **kw):
    """The real Phase 2 -> register -> Phase 4 -> Phase 5 flow on one scan (needs the temporary database of the calling test)."""
    r = scan(n, **kw)
    sink = []
    r["campaign_fingerprint"], r["campaign_matches"] = dna.find_matches(r, history_sink=sink)
    r["campaign_intel"] = ci.build_campaign_intel(r["campaign_fingerprint"], r["campaign_matches"], sink)
    r["evidence_register"], r["scan_findings"] = ia.build_scan_evidence(r)
    r["entity_graph"] = eg.build_entity_graph(r)
    return r, op.build_operator_intel(r)


def operator_rows(path):
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT * FROM operator_observations").fetchall()
    finally:
        conn.close()


class Base(unittest.TestCase):
    def setUp(self):
        self.db = _tmp_db(self)


# =============================================================================================== time & geometry utilities
class TimeNormalisation(unittest.TestCase):
    def test_zone_aware_formats_normalise_to_the_same_utc_instant(self):
        a = op.normalise_time("2026-11-20T10:08:00+00:00")[0]
        b = op.normalise_time("2026-11-20T11:08:00+01:00")[0]
        c = op.normalise_time("Fri, 20 Nov 2026 21:08:00 +1100")[0]
        d = op.normalise_time("2026-11-20T10:08:00Z")[0]
        e = op.normalise_time(datetime(2026, 11, 20, 5, 8, tzinfo=timezone(timedelta(hours=-5))))[0]
        self.assertEqual({a, b, c, d, e}, {datetime(2026, 11, 20, 10, 8, tzinfo=timezone.utc)})
        for dt in (a, b, c, d, e):
            self.assertEqual(dt.utcoffset().total_seconds(), 0)

    def test_a_timestamp_without_a_zone_is_never_guessed(self):
        for text in ("2026-11-20T10:08:00", "Fri, 20 Nov 2026 10:08:00", datetime(2026, 11, 20, 10, 8)):
            utc, ok, note = op.normalise_time(text)
            self.assertEqual((utc, ok), (None, False))
            self.assertIn("time zone", note)

    def test_rfc2822_minus_0000_is_read_as_utc(self):
        utc, ok, _ = op.normalise_time("Fri, 20 Nov 2026 10:08:00 -0000")
        self.assertEqual((utc, ok), (datetime(2026, 11, 20, 10, 8, tzinfo=timezone.utc), True))

    def test_missing_invalid_and_implausible_values_are_rejected_without_raising(self):
        for bad in (None, "", "   ", "not a date", "2026-13-45T99:99:99+00:00", 12345, [], {}, "Fri, 99 Zzz 2026 10:08:00 +0000",
                    "1969-12-31T23:59:59+00:00", "2200-01-01T00:00:00+00:00", object()):
            with self.subTest(bad=repr(bad)[:30]):
                utc, ok, note = op.normalise_time(bad)
                self.assertEqual((utc, ok), (None, False))
                self.assertTrue(note)

    def test_explicit_zone_detection(self):
        for text in ("Fri, 20 Nov 2026 10:08:00 +0200", "Fri, 20 Nov 2026 10:08:00 GMT", "Fri, 20 Nov 2026 10:08:00 UTC",
                     "Fri, 20 Nov 2026 10:08:00 -0500 (EST)", "Fri, 20 Nov 2026 10:08:00 PST"):
            self.assertTrue(op.has_explicit_zone(text), text)
        for text in ("Fri, 20 Nov 2026 10:08:00", "", None, "10:08"):
            self.assertFalse(op.has_explicit_zone(text), repr(text))


class Geometry(unittest.TestCase):
    def test_haversine_known_distances(self):
        self.assertAlmostEqual(op.haversine_km(0.0, 10.0, 0.0, 10.0), 0.0, places=6)
        self.assertAlmostEqual(op.haversine_km(0.0, 0.0, 0.0, 1.0), 111.19, delta=0.2)
        self.assertGreater(op.haversine_km(*FRANKFURT, *SYDNEY), 15000)
        self.assertLess(op.haversine_km(*FRANKFURT, *PARIS), 520)
        self.assertAlmostEqual(op.haversine_km(*FRANKFURT, *SYDNEY), op.haversine_km(*SYDNEY, *FRANKFURT), places=6)

    def test_coordinates_are_validated_never_invented(self):
        self.assertEqual(op.valid_coords(50.1, 8.7), (50.1, 8.7))
        self.assertEqual(op.valid_coords("50.1", "8.7"), (50.1, 8.7))
        for bad in ((None, None), (0, 0), (0.0, 0.0), (91, 0), (-91, 10), (10, 181), (10, -181), ("x", 1), (float("nan"), 1),
                    (float("inf"), 1), (True, 1), ([], {}), ("", "")):
            with self.subTest(bad=repr(bad)):
                self.assertIsNone(op.valid_coords(*bad))


# ================================================================================================================ journey
class ImpossibleJourney(unittest.TestCase):
    def test_a_clearly_implausible_transition_is_detected_with_numbers_and_an_explanation(self):
        j = op.assess_journey(ev(1, when="2026-11-20T10:00:00+00:00"), ev(2, *SYDNEY, when="2026-11-20T10:08:00+00:00", city="Sydney", country="Australia"))
        self.assertEqual(j["status"], "implausible")
        self.assertEqual(j["elapsed_seconds"], 480.0)
        self.assertGreater(j["distance_km"], 15000)
        self.assertLess(j["effective_distance_km"], j["distance_km"])                       # the uncertainty allowance was applied
        self.assertGreater(j["required_speed_kmh"], j["config"]["threshold_kmh"])
        self.assertEqual((j["from"]["place"], j["to"]["place"]), ("Frankfurt, Germany", "Sydney, Australia"))
        text = j["explanation"]
        for needle in ("anomaly in the IP observations", "does not show where any person was", "900 km/h", "approximate"):
            self.assertIn(needle, text)
        self.assertNotIn("attacker travelled", text.lower())

    def test_a_plausible_transition_is_not_suspicious(self):
        j = op.assess_journey(ev(1, when="2026-11-20T10:00:00+00:00"), ev(2, *PARIS, when="2026-11-20T14:00:00+00:00"))
        self.assertEqual(j["status"], "plausible")
        self.assertLess(j["required_speed_kmh"], 900)

    def test_nearby_locations_are_within_the_geolocation_uncertainty(self):
        j = op.assess_journey(ev(1, 50.0, 10.0), ev(2, 50.0, 12.0, when="2026-11-20T10:00:01+00:00"))          # ~143 km apart
        self.assertEqual((j["status"], j["reasons"]), ("plausible", ["within_geolocation_uncertainty"]))

    def test_missing_timestamps_never_make_a_finding(self):
        for bad in (None, ""):
            j = op.assess_journey(ev(1), ev(2, *SYDNEY, when=bad))
            self.assertEqual(j["status"], "insufficient_evidence")
            self.assertIn("second:no_timestamp", j["reasons"])
            self.assertIsNone(j["required_speed_kmh"])

    def test_invalid_and_unreliable_timestamps_never_make_a_finding(self):
        j = op.assess_journey(ev(1), ev(2, *SYDNEY, when="not a date"))
        self.assertEqual((j["status"], "second:invalid_timestamp" in j["reasons"]), ("insufficient_evidence", True))
        j = op.assess_journey(ev(1), ev(2, *SYDNEY, when="2026-11-20T10:08:00"))                       # no zone: not guessed
        self.assertEqual((j["status"], "second:invalid_timestamp" in j["reasons"]), ("insufficient_evidence", True))
        j = op.assess_journey(ev(1, time_reliable=False), ev(2, *SYDNEY, when="2026-11-20T10:08:00+00:00"))
        self.assertEqual((j["status"], "first:timestamp_unreliable" in j["reasons"]), ("insufficient_evidence", True))

    def test_missing_or_unusable_coordinates_never_make_a_finding(self):
        for bad in ({"lat": None}, {"lon": None}, {"lat": 0, "lon": 0}, {"lat": "x"}, {"lat": 95.0}, {"lat": float("nan")}):
            with self.subTest(bad=repr(bad)):
                kw = {"lat": SYDNEY[0], "lon": SYDNEY[1]}
                kw.update(bad)
                j = op.assess_journey(ev(1), ev(2, when="2026-11-20T10:08:00+00:00", **kw))
                self.assertEqual(j["status"], "insufficient_evidence")
                self.assertIn("second:no_coordinates", j["reasons"])

    def test_unattributable_locations_never_make_a_finding_however_far_apart(self):
        for code in ("infrastructure_location", "provider_not_operator", "not_client_submission", "ip_unsuitable", "origin_low_confidence"):
            with self.subTest(code=code):
                bad = ev(2, *SYDNEY, when="2026-11-20T10:08:00+00:00", attributable=False, attribution=[code])
                j = op.assess_journey(ev(1), bad)
                self.assertEqual(j["status"], "insufficient_evidence")
                self.assertIn("second:location_not_attributable", j["reasons"])
                self.assertIn("second:" + code, j["reasons"])
                self.assertIn("No suspicious finding is made", j["explanation"])

    def test_the_same_scan_and_missing_events_are_insufficient(self):
        self.assertEqual(op.assess_journey(ev(1), ev(1))["status"], "insufficient_evidence")
        self.assertIn("same_event", op.assess_journey(ev(1), ev(1))["reasons"])
        for bad in (None, {}, "x", 5):
            self.assertEqual(op.assess_journey(ev(1), bad)["status"], "insufficient_evidence")
            self.assertEqual(op.assess_journey(bad, ev(1))["status"], "insufficient_evidence")

    def test_time_zone_normalisation_decides_the_elapsed_time(self):
        a = ev(1, when="2026-11-20T10:00:00+00:00")
        for b_time in ("2026-11-20T11:08:00+01:00", "Fri, 20 Nov 2026 21:08:00 +1100", "2026-11-20T10:08:00Z", "2026-11-20T05:08:00-05:00"):
            with self.subTest(b_time=b_time):
                j = op.assess_journey(a, ev(2, *SYDNEY, when=b_time))
                self.assertEqual((j["status"], j["elapsed_seconds"]), ("implausible", 480.0))
        # the same wall-clock digits in different zones are NOT the same instant: 10:08 at +10:00 is 00:08 UTC, 10 hours earlier
        j = op.assess_journey(a, ev(2, *SYDNEY, when="2026-11-20T10:08:00+10:00"))
        self.assertEqual(j["elapsed_seconds"], 9 * 3600 + 52 * 60.0)
        self.assertEqual(j["from"]["scan_id"], sid(2))                                       # ordered by UTC time, not by argument order

    def test_the_result_does_not_depend_on_argument_order(self):
        a, b = ev(1, when="2026-11-20T10:00:00+00:00"), ev(2, *SYDNEY, when="2026-11-20T10:08:00+00:00")
        j1, j2 = op.assess_journey(a, b), op.assess_journey(b, a)
        for k in ("status", "elapsed_seconds", "distance_km", "required_speed_kmh", "from", "to"):
            self.assertEqual(j1[k], j2[k])

    def test_speed_exactly_at_the_threshold_is_plausible_and_just_above_is_implausible(self):
        a, b = ev(1, 0.0, 10.0, when="2026-11-20T10:00:00+00:00"), ev(2, 0.0, 12.0, when="2026-11-20T11:00:00+00:00")
        cfg = dict(geo_uncertainty_km=0.0, clock_skew_s=0.0, min_effective_km=0.0)
        speed = op.haversine_km(0.0, 10.0, 0.0, 12.0) / (3600.0 / 3600.0)                    # distance / 1 hour, the engine's own expression
        self.assertEqual(op.assess_journey(a, b, max_speed_kmh=speed, **cfg)["status"], "plausible")
        self.assertEqual(op.assess_journey(a, b, max_speed_kmh=speed * (1 - 1e-9), **cfg)["status"], "implausible")
        self.assertEqual(op.assess_journey(a, b, max_speed_kmh=speed * (1 + 1e-9), **cfg)["status"], "plausible")

    def test_thresholds_are_configurable_and_the_allowances_widen_what_is_plausible(self):
        a, b = ev(1, when="2026-11-20T10:00:00+00:00"), ev(2, *PARIS, when="2026-11-20T10:10:00+00:00")        # ~480 km in 10 minutes
        self.assertEqual(op.assess_journey(a, b)["status"], "implausible")                                  # default: 900 km/h
        self.assertEqual(op.assess_journey(a, b, max_speed_kmh=2000.0)["status"], "plausible")
        self.assertEqual(op.assess_journey(a, b, geo_uncertainty_km=300.0)["status"], "plausible")            # the uncertainty swallows it
        self.assertEqual(op.assess_journey(a, b, clock_skew_s=3 * 3600.0)["status"], "plausible")             # a large clock-skew allowance too
        self.assertEqual(op.assess_journey(a, b)["config"]["threshold_kmh"], op.MAX_PLAUSIBLE_SPEED_KMH)

    def test_zero_effective_distance_needs_zero_speed(self):
        a, b = ev(1, 10.0, 10.0), ev(2, 10.0, 10.0, when=T10)                                              # same place, same second
        j = op.assess_journey(a, b, geo_uncertainty_km=0.0, clock_skew_s=0.0, min_effective_km=0.0)
        self.assertEqual(j["status"], "plausible")


# ======================================================================================================= event extraction
class EventExtraction(unittest.TestCase):
    def test_a_client_submission_with_register_evidence_is_attributable(self):
        e = op.extract_event(with_register(1))
        self.assertEqual((e["ip"], e["attributable"], e["attribution"]), ("8.8.4.4", True, []))
        self.assertEqual((e["lat"], e["lon"], e["country_code"], e["city"]), (50.11, 8.68, "DE", "Frankfurt"))
        self.assertEqual(e["event_time"], "2026-11-20T10:00:00+00:00")
        self.assertTrue(e["time_reliable"])
        self.assertEqual(set(e["evidence"]), {"geo", "origin", "time"})
        self.assertEqual(e["origin_confidence"], 70)

    def test_evidence_ids_are_the_registers_own_entries(self):
        r = with_register(1)
        e = op.extract_event(r)
        by_id = {x["id"]: x for x in r["evidence_register"]}
        self.assertEqual((by_id[e["evidence"]["geo"]]["type"], by_id[e["evidence"]["geo"]]["source"]), ("GeoIP", "geolocate"))
        self.assertEqual((by_id[e["evidence"]["origin"]]["type"], by_id[e["evidence"]["origin"]]["source"]), ("infrastructure", "origin_intel"))
        t = by_id[e["evidence"]["time"]]
        self.assertEqual((t["type"], t["source"], t["origin"], t["status"]), ("timestamp", "origin_route", "untrusted_claim", "ok"))
        self.assertEqual(t["metadata"]["ip"], "8.8.4.4")

    def test_a_mail_server_is_not_an_operator_location(self):
        for protocol in ("ESMTP", "ESMTPS", "SMTP", "", "LMTP"):
            with self.subTest(protocol=protocol):
                e = op.extract_event(with_register(1, protocol=protocol))
                self.assertFalse(e["attributable"])
                self.assertIn("not_client_submission", e["attribution"])

    def test_authenticated_submission_protocols_and_x_originating_ip_count_as_client_submission(self):
        for protocol in ("ESMTPA", "ESMTPSA", "esmtpsa", "UTF8SMTPSA"):
            self.assertTrue(op.extract_event(with_register(1, protocol=protocol))["attributable"], protocol)
        e = op.extract_event(with_register(1, protocol="ESMTP", originating=True))
        self.assertTrue(e["attributable"])
        e = op.extract_event(with_register(1, protocol="ESMTP", originating=False))
        self.assertFalse(e["attributable"])

    def test_vpn_proxy_tor_hosting_cdn_cloud_and_mobile_locations_are_not_operator_locations(self):
        for infra in ("vpn", "proxy", "tor", "hosting"):
            with self.subTest(infra=infra):
                e = op.extract_event(with_register(1, infra=infra))
                self.assertFalse(e["attributable"])
                self.assertIn("infrastructure_location", e["attribution"])
        for provider in ("AS13335 Cloudflare, Inc.", "AS16509 Amazon.com, Inc.", "AS15169 Google LLC", "AS8075 Microsoft Corporation",
                         "AS12345 Example Mobile Networks", "AS777 Acme Wireless", "AS55 Fastly", "AS54113 Akamai Technologies", "AS24940 Hetzner Online"):
            with self.subTest(provider=provider):
                e = op.extract_event(with_register(1, asn=provider, isp=provider))
                self.assertFalse(e["attributable"])
                self.assertIn("provider_not_operator", e["attribution"])
        r = with_register(1)
        r["geo"]["origin"]["tor_exit_confirmed"] = True
        self.assertIn("infrastructure_location", op.extract_event(r)["attribution"])

    def test_private_reserved_multicast_scoped_and_malformed_ips_are_unusable(self):
        for ip in ("10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.1.1", "172.16.0.9", "192.0.2.1", "224.0.0.1", "::1", "fd00::1", "fe80::1",
                   "fe80::1%eth0", "2001:db8::1", "not-an-ip", "999.1.1.1", "", None, 5):
            with self.subTest(ip=ip):
                e = op.extract_event(with_register(1, ip=ip))
                self.assertIsNone(e["ip"])
                self.assertFalse(e["attributable"])
                self.assertIn("ip_unsuitable", e["attribution"])
                self.assertIsNone(e["lat"])                                                                    # no coordinates without a usable IP

    def test_low_confidence_missing_or_disagreeing_origin_assessments_are_not_attributable(self):
        self.assertIn("origin_low_confidence", op.extract_event(with_register(1, confidence=10))["attribution"])
        self.assertIn("origin_disagreement", op.extract_event(with_register(1, selected="1.1.1.1"))["attribution"])
        self.assertIn("no_origin_assessment", op.extract_event(with_register(1, with_origin=False))["attribution"])
        self.assertEqual(op.extract_event(with_register(1, selected="1.1.1.1"))["origin_confidence"], 0)

    def test_missing_register_evidence_means_missing_location_and_time_evidence(self):
        r = scan(1)
        e = op.extract_event(r)                                                    # no evidence_register at all
        self.assertIn("no_location_evidence", e["attribution"])
        self.assertFalse(e["attributable"])
        self.assertEqual((e["event_time"], e["time_reliable"], e["evidence"]), (None, False, {}))

    def test_timestamp_reliability_follows_the_header_and_the_route(self):
        e = op.extract_event(with_register(1, when="Fri, 20 Nov 2026 10:00:00"))                  # no zone stated: UTC was assumed
        self.assertEqual((e["event_time"], e["time_reliable"]), ("2026-11-20T10:00:00+00:00", False))
        self.assertIn("time zone", e["time_note"])
        e = op.extract_event(with_register(1, ts_flags=("TS_BACKWARDS",)))
        self.assertFalse(e["time_reliable"])
        self.assertIn("backwards", e["time_note"])
        e = op.extract_event(with_register(1, when="Fri, 20 Nov 2026 12:00:00 +0200"))
        self.assertEqual((e["event_time"], e["time_reliable"]), ("2026-11-20T10:00:00+00:00", True))     # normalised to UTC

    def test_a_timestamp_for_a_different_ip_is_never_used(self):
        r = with_register(1)
        for x in r["evidence_register"]:
            if x["type"] == "timestamp":
                x["metadata"]["ip"] = "1.1.1.1"
        e = op.extract_event(r)
        self.assertEqual((e["event_time"], e["time_reliable"]), (None, False))
        self.assertNotIn("time", e["evidence"])

    def test_malformed_results_never_raise(self):
        for bad in (None, {}, [], "x", 5, {"scan_id": "SC-1"}, {"scan_id": sid(1)}, {"scan_id": sid(1), "geo": "x", "origin_intel": [], "evidence_register": 7},
                    {"scan_id": sid(1), "geo": {"origin": {"ip": "8.8.4.4", "lat": "x"}}, "origin_intel": {"route": "x", "corroboration": 3}}):
            with self.subTest(bad=repr(bad)[:40]):
                e = op.extract_event(bad)
                self.assertTrue(e is None or isinstance(e, dict))

    def test_the_result_is_not_mutated(self):
        r = with_register(1)
        before = copy.deepcopy(r)
        op.extract_event(r)
        self.assertEqual(r, before)

    def test_event_view_never_carries_the_ip_of_a_stored_event(self):
        e = op.extract_event(with_register(1))
        self.assertEqual(op.event_view(e, current=True)["ip"], "8.8.4.4")
        self.assertNotIn("ip", op.event_view(e))
        self.assertNotIn("ip_id", op.event_view(e, current=True))


# ============================================================================================ the evidence-register entry
class OriginTimestampEvidence(unittest.TestCase):
    def entries(self, r):
        return [e for e in r["evidence_register"] if e["type"] == "timestamp"]

    def test_one_entry_records_the_origin_hop_time_as_an_untrusted_claim(self):
        r = with_register(1)
        (t,) = self.entries(r)
        self.assertEqual((t["source"], t["origin"], t["status"], t["source_reference"]), ("origin_route", "untrusted_claim", "ok", "result.origin_intel.route"))
        self.assertEqual(len([e for e in r["evidence_register"] if e["source"] == "origin_intel"]), 1)       # the existing single origin_intel entry is untouched
        self.assertEqual(t["metadata"], {"ip": "8.8.4.4", "hop": 1, "utc": "2026-11-20T10:00:00+00:00", "tz_explicit": True, "ts_anomaly": False})
        self.assertIn("2026-11-20 10:00:00 UTC", t["observation"])
        self.assertEqual(t["scan_id"], sid(1))

    def test_a_zone_less_stamp_is_partial_and_a_backwards_stamp_is_flagged(self):
        (t,) = self.entries(with_register(1, when="Fri, 20 Nov 2026 10:00:00"))
        self.assertEqual((t["status"], t["metadata"]["tz_explicit"]), ("partial", False))
        (t,) = self.entries(with_register(1, ts_flags=("TS_BACKWARDS",)))
        self.assertTrue(t["metadata"]["ts_anomaly"])

    def test_no_entry_without_a_usable_selected_origin(self):
        self.assertEqual(self.entries(with_register(1, with_origin=False)), [])
        r = scan(1)
        r["origin_intel"]["selected_ip"] = None
        r["evidence_register"], _ = ia.build_scan_evidence(r)
        self.assertEqual(self.entries(r), [])
        r = scan(1)
        r["origin_intel"]["confidence"] = "high"                                   # malformed origin output is never evidence
        r["evidence_register"], _ = ia.build_scan_evidence(r)
        self.assertEqual(self.entries(r), [])

    def test_a_missing_stamp_records_no_entry_and_no_event_time(self):
        r = scan(1)
        r["origin_intel"]["route"][0]["ts"] = None
        r["evidence_register"], r["scan_findings"] = ia.build_scan_evidence(r)
        self.assertEqual(self.entries(r), [])                                      # no "missing" gap entry that would need its own finding
        e = op.extract_event(r)
        self.assertEqual((e["event_time"], e["time_reliable"]), (None, False))
        self.assertNotIn("time", e["evidence"])
        self.assertEqual(len([x for x in r["evidence_register"] if x["source"] == "origin_intel"]), 1)
        self.assertEqual(ia.validate_scan_register(r), [])
    def test_the_new_section_precedes_campaign_intelligence_and_no_id_is_renumbered(self):
        db = _tmp_db(self)
        analyze(1)
        r, _ = analyze(2)
        ids = [int(e["id"][1:]) for e in r["evidence_register"]]
        self.assertEqual(ids, list(range(1, len(ids) + 1)))
        t = [int(e["id"][1:]) for e in r["evidence_register"] if e["type"] == "timestamp"]
        intel = [int(e["id"][1:]) for e in r["evidence_register"] if e["source"] == "campaign_intel"]
        self.assertTrue(t and intel)
        self.assertLess(max(t), min(intel))                                        # Phase 3 intelligence stays the last section
        self.assertGreater(min(t), max(int(e["id"][1:]) for e in r["evidence_register"] if e["source"] == "attack_dna"))


# ============================================================================================== correlation, pure
def shared(typ, label, ev_ids=("S5",), n=2, rel="links to"):
    return {"type": typ, "label": label, "entity_id": "%s:%032x" % (typ, hash(label) & 0xffffffff), "evidence": list(ev_ids),
            "historical": ["%s:S5" % sid(n)], "rels": [rel]}


STRONG_DNA = {"classification": "strong", "score": 0.72, "qualifying_families": ["auth_anomalies", "url_tactics", "domain_alignment"],
              "matched_families": {"auth_anomalies": ["high:SPF fail"], "url_tactics": ["punycode"], "domain_alignment": ["x"]}}
WEAK_DNA = {"classification": "weak", "score": 0.31, "qualifying_families": ["auth_anomalies"], "matched_families": {"auth_anomalies": ["high:SPF fail"]}}


def far(n=2, **kw):
    """An observation with NOTHING in common with ev(1): another network, another time of day, another IP hash."""
    base = {"ip_id": "ip:far%d" % n, "asn": "AS777 Elsewhere", "event_time": "2026-11-21T22:00:00+00:00"}
    base.update(kw)
    return ev(n, **base)


def pair(cur=None, other=None, dna_match=None, dna_ev=("S3", "S4"), sh=None, graph_ok=True):
    return op.evaluate_pair(cur if cur is not None else ev(1), other if other is not None else far(), sid(2), dna=dna_match,
                            dna_evidence=list(dna_ev) if dna_match else [], shared=sh, graph_ok=graph_ok)


def total_from(signals):
    by = {}
    for s in signals:
        by[s["category"]] = by.get(s["category"], 0) + s["points"]
    return min(op.CONFIDENCE_CAP, sum(min(op.CATEGORY_CAPS[c], p) for c, p in by.items()))


class CommonOperatorCorrelation(unittest.TestCase):
    def test_same_infrastructure_is_a_directly_observed_relationship(self):
        p = pair(sh=[shared("url", "evil.example")])
        self.assertEqual((p["level"], p["correlation_type"], p["infrastructure"]), ("observed", "same_infrastructure", "shared"))
        self.assertEqual([s["code"] for s in p["signals"]], ["shared_url"])
        self.assertEqual(p["signals"][0]["kind"], "observed")
        self.assertIn("Directly observed", p["explanation"])
        self.assertIn("does not by itself show that one operator controls them", p["explanation"])

    def test_same_infrastructure_plus_attack_dna_is_a_strongly_supported_correlation(self):
        p = pair(dna_match=STRONG_DNA, sh=[shared("url", "evil.example")])
        self.assertEqual((p["level"], p["band"]), ("strong", "High"))
        self.assertEqual(sorted(p["independent_categories"]), ["campaign_fingerprint", "infrastructure"])
        self.assertGreaterEqual(p["confidence"], op.BAND_HIGH)
        self.assertIn("strongly supported correlation, not proof", p["explanation"])

    def test_different_infrastructure_with_strong_behavioural_similarity_is_strong_only_with_several_independent_signals(self):
        a = ev(1, when="2026-11-20T10:00:00+00:00")
        b = ev(2, 51.5, -0.12, when="2026-11-21T10:30:00+00:00", ip_id="ip:other", country="United Kingdom", country_code="GB", city="London")
        p = pair(a, b, dna_match=STRONG_DNA)                                       # same ASN + same time-of-day window + 3 behavioural families
        self.assertEqual({s["code"] for s in p["signals"]}, {"dna_strong", "timing_window", "same_asn"})
        self.assertEqual((p["level"], p["correlation_type"], p["infrastructure"]), ("strong", "different_infrastructure", "different"))
        self.assertIn("may be related despite using different infrastructure because the available evidence shows similarities in their "
                      "operational behaviour", p["explanation"])
        self.assertIn("still not proof of a common operator", p["explanation"])

    def test_different_infrastructure_with_weak_similarity_stays_weak(self):
        b = ev(2, ip_id="ip:other", asn="AS777 Other", event_time="2026-11-21T20:00:00+00:00", time_reliable=False)
        for d in (WEAK_DNA, {**STRONG_DNA, "qualifying_families": ["auth_anomalies"]}):
            p = pair(ev(1), b, dna_match=d)
            self.assertEqual((p["level"], p["correlation_type"]), ("weak", "different_infrastructure"))
            self.assertLess(p["confidence"], op.STRONG_POINTS)
            self.assertIn("weak similarity only", p["explanation"].lower())

    def test_a_shared_hosting_provider_alone_is_not_enough(self):
        cur = ev(1, infra="hosting", ip="8.8.4.4")
        p = pair(cur, far(ip_id=cur["ip_id"]), sh=[shared("ip", "8.8.4.4")])
        self.assertEqual((p["level"], p["correlation_type"], p["confidence"], p["band"]), ("insufficient", "shared_provider_only", 0, "None"))
        self.assertEqual([s["code"] for s in p["signals"]], ["shared_provider_ip"])
        self.assertIn("not enough evidence", p["explanation"].lower())
        self.assertIn("not evidence of a common operator", p["explanation"])

    def test_a_shared_mail_relay_ip_is_only_weak_context(self):
        relay = ev(1, ip="8.8.4.4", attributable=False, attribution=["not_client_submission"])      # no evidence a client connected from it
        p = pair(relay, far(ip_id=relay["ip_id"]), sh=[shared("ip", "8.8.4.4")])
        self.assertEqual([s["code"] for s in p["signals"]], ["shared_provider_ip"])
        self.assertEqual((p["level"], p["correlation_type"]), ("insufficient", "shared_provider_only"))
        client = ev(1, ip="8.8.4.4")                                                               # attributable client submission
        p = pair(client, far(ip_id=client["ip_id"]), sh=[shared("ip", "8.8.4.4")])
        self.assertEqual(([s["code"] for s in p["signals"]], p["level"]), (["shared_ip"], "observed"))
        q = pair(relay, far(ip_id=relay["ip_id"]), graph_ok=False)                                 # the same rule applies to the stored-hash fallback
        self.assertEqual([s["code"] for s in q["signals"] if s["category"] == "infrastructure"], ["shared_provider_ip"])

    def test_the_same_network_alone_is_not_enough(self):
        p = pair(ev(1), ev(2, ip_id="ip:other", event_time="2026-11-21T22:00:00+00:00"))
        self.assertEqual([s["code"] for s in p["signals"]], ["same_asn"])
        self.assertEqual(p["level"], "insufficient")

    def test_a_shared_generic_provider_domain_says_nothing(self):
        for label in ("gmail.com", "outlook.com", "sub.google.com", "amazonaws.com"):
            with self.subTest(label=label):
                p = pair(sh=[shared("domain", label)])
                self.assertEqual((p["signals"][0]["code"], p["signals"][0]["points"], p["level"]), ("shared_generic_domain", 0, "insufficient"))
        p = pair(sh=[shared("domain", "evil-corp.example")])
        self.assertEqual((p["signals"][0]["code"], p["level"]), ("shared_domain", "observed"))

    def test_shared_specific_entities_are_weighted_by_how_specific_they_are(self):
        points = {t: pair(sh=[shared(t, l)])["signals"][0]["points"] for t, l in (("url", "x.example"), ("sender", None), ("domain", "x.example"), ("ip", "8.8.4.4"))}
        self.assertEqual(points, {"url": 40, "sender": 25, "domain": 20, "ip": 20})
        self.assertGreater(points["url"], points["sender"])

    def test_a_similar_subject_is_never_evidence(self):
        a, b = ev(1, subject="Invoice 123"), ev(2, ip_id="ip:other", asn="AS1 Other", subject="Invoice 123", event_time="2026-11-25T20:00:00+00:00")
        p = pair(a, b)
        self.assertEqual((p["level"], p["signals"]), ("insufficient", []))
        for s in p["signals"] + [p]:
            self.assertNotIn("subject", json.dumps(s).lower())

    def test_missing_attack_dna_data_removes_only_that_signal(self):
        p = pair(dna_match=None, sh=[shared("url", "x.example")])
        self.assertEqual([s["code"] for s in p["signals"]], ["shared_url"])
        p = pair(dna_match={"classification": "none", "qualifying_families": []})
        self.assertEqual((p["signals"], p["level"]), ([], "insufficient"))

    def test_attack_dna_context_only_families_never_count(self):
        d = {"classification": "strong", "score": 0.8, "qualifying_families": ["infra_class", "structural"]}
        self.assertEqual([s["code"] for s in pair(dna_match=d)["signals"] if s["category"] == "campaign_fingerprint"], [])
        self.assertIsNone(op._dna_signal({"classification": "strong", "qualifying_families": []}, ["S1"]))
        self.assertIsNone(op._dna_signal({"classification": "none", "qualifying_families": ["auth_anomalies"]}, ["S1"]))

    def test_an_attack_dna_match_without_register_evidence_is_skipped_and_counted(self):
        p = pair(dna_match=STRONG_DNA, dna_ev=())
        self.assertFalse([s for s in p["signals"] if s["category"] == "campaign_fingerprint"])
        self.assertEqual(p["skipped_no_evidence"], 1)
        self.assertTrue(any("left out" in x for x in p["limitations"]))

    def test_missing_entity_graph_data_means_infrastructure_cannot_be_compared(self):
        p = pair(dna_match=STRONG_DNA, graph_ok=False)
        self.assertEqual((p["infrastructure"], p["correlation_type"]), ("unknown", "behavioural_only"))
        self.assertTrue(any("could not be compared" in x for x in p["limitations"]))
        self.assertNotIn("despite using different infrastructure", p["explanation"])

    def test_a_missing_stored_observation_limits_the_comparison(self):
        p = op.evaluate_pair(ev(1), None, sid(2), dna=WEAK_DNA, dna_evidence=["S3"], shared=[], graph_ok=True)
        self.assertEqual([s["code"] for s in p["signals"]], ["dna_weak"])
        self.assertIsNone(p["other_event"])
        self.assertTrue(any("No stored observation" in x for x in p["limitations"]))

    def test_duplicate_shared_entities_count_once(self):
        p = pair(sh=[shared("url", "x.example"), shared("url", "x.example"), shared("url", "x.example", ("S6",))])
        self.assertEqual([s["code"] for s in p["signals"]], ["shared_url"])
        self.assertEqual(p["confidence"], 40)

    def test_a_shared_entity_without_register_evidence_is_not_used(self):
        p = pair(sh=[shared("url", "x.example", ev_ids=())])
        self.assertEqual((p["signals"], p["skipped_no_evidence"], p["level"]), ([], 1, "insufficient"))

    def test_conflicting_or_unreliable_timestamps_remove_the_timing_signal_only(self):
        for bad in ({"time_reliable": False}, {"event_time": None}, {"event_time": "garbage"}):
            with self.subTest(bad=bad):
                p = pair(ev(1), ev(2, **bad), dna_match=WEAK_DNA)
                self.assertNotIn("timing_window", [s["code"] for s in p["signals"]])
                self.assertIn("dna_weak", [s["code"] for s in p["signals"]])
        p = pair(ev(1, time_reliable=False), ev(2, ip_id="ip:o"), dna_match=WEAK_DNA)
        self.assertNotIn("timing_window", [s["code"] for s in p["signals"]])

    def test_the_timing_window_is_circular_across_midnight(self):
        a = ev(1, when="2026-11-20T23:30:00+00:00")
        b = ev(2, ip_id="ip:o", when="2026-11-23T00:20:00+00:00")                  # 50 minutes apart on the clock, 3 days apart
        self.assertIn("timing_window", [s["code"] for s in pair(a, b)["signals"]])
        c = ev(2, ip_id="ip:o", when="2026-11-23T03:30:00+00:00")
        self.assertNotIn("timing_window", [s["code"] for s in pair(a, c)["signals"]])

    def test_the_same_origin_ip_is_detected_from_stored_hashes_when_the_graph_is_unavailable(self):
        cur = ev(1)
        p = pair(cur, ev(2, ip_id=cur["ip_id"]), graph_ok=False)
        self.assertEqual([s["code"] for s in p["signals"] if s["category"] == "infrastructure"], ["shared_ip"])
        self.assertEqual(p["infrastructure"], "shared")

    def test_confidence_is_the_documented_sum_of_capped_category_points(self):
        cases = [pair(sh=[shared("url", "x.example")]), pair(dna_match=STRONG_DNA, sh=[shared("url", "x.example"), shared("domain", "y.example")]),
                 pair(dna_match=WEAK_DNA), pair(dna_match=STRONG_DNA), pair(sh=[shared("url", "a.example"), shared("sender", None), shared("ip", "8.8.4.4"),
                                                                                shared("domain", "d.example")], dna_match=STRONG_DNA)]
        for p in cases:
            with self.subTest(level=p["level"], conf=p["confidence"]):
                expected = total_from(p["signals"])
                self.assertEqual(p["confidence"], expected if p["level"] != "insufficient" else 0)
                self.assertLessEqual(p["confidence"], op.CONFIDENCE_CAP)
                self.assertEqual(sum(int(x.split()[0].lstrip("+")) for x in p["confidence_basis"]), sum(s["points"] for s in p["signals"] if s["points"] > 0))
                self.assertEqual(p["band"], "None" if p["level"] == "insufficient" else op._band(p["confidence"]))

    def test_high_confidence_always_needs_more_than_one_kind_of_evidence(self):
        weak_only = [pair(cur=ev(1, infra="hosting", ip="8.8.4.4"), sh=[shared("ip", "8.8.4.4")]), pair(), pair(dna_match=WEAK_DNA),
                     pair(sh=[shared("domain", "gmail.com")]), pair(sh=[shared("url", "x.example")])]
        for p in weak_only:
            self.assertNotEqual(p["band"], "High")
            self.assertNotEqual(p["level"], "strong")
        for sig in (("url", "x.example"), ("sender", None)):
            self.assertLess(pair(sh=[shared(*sig)])["confidence"], op.BAND_HIGH)               # a single shared entity can never be High
        self.assertEqual(pair(dna_match=STRONG_DNA, sh=[shared("url", "x.example")])["band"], "High")

    def test_a_shared_hosting_provider_or_similar_subject_can_never_reach_strong(self):
        for p in (pair(cur=ev(1, infra="hosting", ip="8.8.4.4"), sh=[shared("ip", "8.8.4.4")]), pair(sh=[shared("domain", "google.com")]), pair()):
            self.assertIn(p["level"], ("insufficient", "weak"))

    def test_explanations_never_overclaim(self):
        all_pairs = [pair(sh=[shared("url", "x.example")]), pair(dna_match=STRONG_DNA, sh=[shared("url", "x.example")]), pair(dna_match=WEAK_DNA),
                     pair(dna_match=STRONG_DNA), pair(), pair(sh=[shared("domain", "gmail.com")]), pair(dna_match=STRONG_DNA, graph_ok=False)]
        for p in all_pairs:
            text = p["explanation"].lower()
            for banned in ("definitely", "certainly", "the same person", "same attacker", "same individual", "proves", "confirmed operator", "identified"):
                self.assertNotIn(banned, text)
            self.assertIn("does not identify a person", text)

    def test_every_signal_cites_register_ids_and_well_formed_historical_references(self):
        p = pair(dna_match=STRONG_DNA, sh=[shared("url", "x.example"), shared("ip", "8.8.4.4")])
        self.assertTrue(p["signals"])
        for s in p["signals"]:
            self.assertTrue(s["evidence"], s["code"])
            self.assertTrue(all(re.match(r"^S\d{1,4}$", i) for i in s["evidence"]))
            self.assertTrue(all(re.match(r"^SC-[0-9a-f]{32}:S\d{1,4}$", i) for i in s["historical_refs"]))
            self.assertIn(s["kind"], ("observed", "inferred"))
        self.assertEqual(p["evidence"], sorted({i for s in p["signals"] for i in s["evidence"]}))

    def test_malformed_signal_inputs_never_raise(self):
        for sh in (None, [], [None], ["x"], [{}], [{"type": "url"}], [{"type": "url", "label": "x", "evidence": ["bad id"]}], [{"type": "mystery", "label": "x", "evidence": ["S1"]}]):
            for d in (None, {}, {"classification": "strong"}, {"classification": "strong", "qualifying_families": "auth_anomalies"}, "x"):
                with self.subTest(sh=repr(sh)[:30], d=repr(d)[:30]):
                    out = op.evaluate_pair(ev(1), ev(2), sid(2), dna=d, dna_evidence=["S1"], shared=sh, graph_ok=True)
                    self.assertIn(out["level"], ("strong", "observed", "weak", "insufficient"))
        out = op.evaluate_pair({}, None, sid(2))
        self.assertEqual(out["level"], "insufficient")


# =========================================================================================================== bounded work
class BoundedProcessing(unittest.TestCase):
    def test_candidates_are_bounded_ranked_and_validated(self):
        matches = [{"scan_id": sid(i), "classification": "strong" if i % 2 else "weak"} for i in range(2, 30)]
        matches += [{"scan_id": "SC-bad", "classification": "strong"}, {"scan_id": sid(1), "classification": "strong"}, {"scan_id": sid(40), "classification": "none"}, None, "x"]
        r = {"campaign_matches": {"status": "ok", "matches": matches}}
        cands, graph_ok = op._candidates(r, sid(1))
        self.assertFalse(graph_ok)
        self.assertEqual(len(cands), op.MAX_RELATED)
        self.assertNotIn(sid(1), cands)
        self.assertNotIn(sid(40), cands)
        self.assertTrue(all(c["dna"]["classification"] == "strong" for c in cands.values()))      # strong matches are kept first
        self.assertEqual(list(cands), sorted(cands))                                                # deterministic order

    def test_shared_entities_become_candidates_with_this_scans_evidence_ids(self):
        r = {"entity_graph": {"status": "ok",
                              "edges": [{"src": {"id": "email:1"}, "dst": {"id": "url:aa"}, "evidence": ["S7", "bad", "S8"], "rel": "links to"}],
                              "shared_entities": [{"entity": {"id": "url:aa", "type": "url", "label": "x.example"},
                                                   "scans": [{"scan_id": sid(2), "rel": "links to", "evidence": ["%s:S9" % sid(2)]}, {"scan_id": "SC-bad", "rel": "x"}]},
                                                  {"entity": "junk"}, {"entity": {"id": 5}}]}}
        cands, graph_ok = op._candidates(r, sid(1))
        self.assertTrue(graph_ok)
        self.assertEqual(list(cands), [sid(2)])
        sh = cands[sid(2)]["shared"][0]
        self.assertEqual((sh["type"], sh["evidence"], sh["historical"]), ("url", ["S7", "S8"], ["%s:S9" % sid(2)]))

    def test_a_failed_graph_is_not_a_graph(self):
        for status in ("unavailable", "key_unavailable", "insufficient_evidence", None):
            cands, graph_ok = op._candidates({"entity_graph": {"status": status, "shared_entities": [{"entity": {"id": "x"}, "scans": [{"scan_id": sid(2)}]}]}}, sid(1))
            self.assertEqual((cands, graph_ok), ({}, False))

    def test_stored_event_counts_and_text_are_bounded(self):
        e = op.extract_event(with_register(1, city="C" * 500, asn="AS1 " + "N" * 500, country="X" * 500))
        self.assertLessEqual(len(e["city"]), 40)
        self.assertLessEqual(len(e["asn"]), 60)
        self.assertLessEqual(len(e["country"]), 40)
        self.assertNotRegex(op._clip("a\x00b\x1fc\x7fd"), r"[\x00-\x1f\x7f]")


# ============================================================================================ orchestration & integration
class FullFlow(Base):
    def test_an_implausible_journey_between_related_attributable_scans_is_found_end_to_end(self):
        r1, oi1 = analyze(1, when="Fri, 20 Nov 2026 10:00:00 +0000")
        self.assertEqual((oi1["status"], oi1["journey"]["status"], oi1["correlations"], oi1["findings"]), ("ok", "insufficient_evidence", [], []))
        r2, oi2 = analyze(2, ip="1.1.1.1", lat=SYDNEY[0], lon=SYDNEY[1], city="Sydney", country="Australia", cc="AU",
                          when="Fri, 20 Nov 2026 10:08:00 +0000")
        self.assertEqual(oi2["status"], "ok")
        self.assertEqual(oi2["journey"]["status"], "detected")
        (jp,) = oi2["journey"]["pairs"]
        self.assertEqual((jp["status"], jp["elapsed_seconds"]), ("implausible", 480.0))
        (f,) = [x for x in oi2["findings"] if x["kind"] == "impossible_journey"]
        self.assertEqual((f["scan_id"], f["related_scan_ids"], f["level"]), (sid(2), [sid(1)], "anomaly"))
        self.assertEqual(f["confidence"]["value"], 70)                              # the lower of the two origin-engine confidences
        self.assertEqual((f["deterministic"], f["ai_generated"]), (True, False))
        reg = {e["id"] for e in r2["evidence_register"]}
        self.assertTrue(f["evidence_ids"] and set(f["evidence_ids"]) <= reg)
        self.assertTrue(all(re.match(r"^SC-[0-9a-f]{32}:S\d+$", x) for x in f["historical_refs"]))
        self.assertTrue(all(x.startswith(sid(1)) for x in f["historical_refs"]))
        self.assertEqual(len(f["timestamps"]), 2)
        self.assertEqual(len(f["geo"]), 2)

    def test_a_plausible_gap_between_the_same_two_scans_is_not_reported(self):
        analyze(1, when="Fri, 20 Nov 2026 10:00:00 +0000")
        _, oi = analyze(2, ip="1.1.1.1", lat=SYDNEY[0], lon=SYDNEY[1], when="Sat, 21 Nov 2026 22:00:00 +0000")     # 36 hours later
        self.assertEqual(oi["journey"]["status"], "none_detected")
        self.assertEqual([f for f in oi["findings"] if f["kind"] == "impossible_journey"], [])

    def test_unattributable_origins_give_insufficient_evidence_not_a_suspicious_finding(self):
        for kw in ({"protocol": "ESMTP"}, {"infra": "vpn"}, {"asn": "AS13335 Cloudflare"}, {"confidence": 10}, {"lat": None}, {"when": "Fri, 20 Nov 2026 10:08:00"}):
            with self.subTest(kw=kw):
                self.db = _tmp_db(self)
                analyze(1, when="Fri, 20 Nov 2026 10:00:00 +0000")
                args = {"ip": "1.1.1.1", "lat": SYDNEY[0], "lon": SYDNEY[1], "when": "Fri, 20 Nov 2026 10:08:00 +0000"}
                args.update(kw)
                _, oi = analyze(2, **args)
                self.assertEqual(oi["journey"]["status"], "insufficient_evidence")
                self.assertEqual([f for f in oi["findings"] if f["kind"] == "impossible_journey"], [])
                self.assertTrue(oi["journey"]["reasons"])

    def test_same_infrastructure_across_separate_attacks_is_directly_observed(self):
        analyze(1, url="http://shared.example/login?a=1", domain="one.example")
        r2, oi = analyze(2, url="http://shared.example/login?a=2", domain="two.example", ip="1.1.1.1")
        (c,) = oi["correlations"]
        self.assertEqual(c["scan_id"], sid(1))
        self.assertIn(c["level"], ("observed", "strong"))
        self.assertEqual((c["correlation_type"], c["infrastructure"]), ("same_infrastructure", "shared"))
        self.assertIn("shared_url", [s["code"] for s in c["signals"]])
        reg = {e["id"] for e in r2["evidence_register"]}
        for s in c["signals"]:
            self.assertTrue(set(s["evidence"]) <= reg)
        self.assertTrue(any(f["kind"] == "operator_correlation" and f["related_scan_ids"] == [sid(1)] for f in oi["findings"]))

    def test_different_infrastructure_with_behavioural_similarity_is_correlated_and_explained(self):
        analyze(1)
        r2, oi = analyze(2, ip="1.1.1.1")                                          # different domains, URLs and IPs; the same behaviour
        cors = [c for c in oi["correlations"] if c["scan_id"] == sid(1)]
        self.assertEqual(len(cors), 1)
        c = cors[0]
        self.assertEqual((c["correlation_type"], c["infrastructure"]), ("different_infrastructure", "different"))
        self.assertIn(c["level"], ("weak", "strong"))
        self.assertFalse([s for s in c["signals"] if s["category"] == "infrastructure"])
        self.assertIn("despite using different infrastructure", c["explanation"])
        self.assertTrue(any(s["category"] == "campaign_fingerprint" for s in c["signals"]))

    def test_unrelated_campaigns_with_only_a_similar_subject_produce_no_correlation(self):
        analyze(1, subject="Your invoice", reply_domain="d1.example", return_domain="d1.example", anomalies=(("high", "SPF fail"),),
                url_flags=(("Punycode host - may render as look-alike Unicode letters",),))
        _, oi = analyze(2, subject="Your invoice", reply_domain="d2.example", return_domain="d2.example", ip="1.1.1.1", asn="AS999 Elsewhere",
                        anomalies=(("high", "DMARC fail"),), url_flags=(("URL shortener hides the real destination",),))
        self.assertEqual(oi["correlations"], [])
        self.assertEqual(oi["findings"], [])
        self.assertEqual(oi["status"], "ok")

    def test_a_shared_hosting_provider_alone_is_insufficient_evidence(self):
        kw = dict(infra="hosting", asn="AS64501 HostCo", isp="HostCo")
        analyze(1, reply_domain="d1.example", return_domain="d1.example", anomalies=(("high", "SPF fail"),),
                url_flags=(("Punycode host - may render as look-alike Unicode letters",),), **kw)
        _, oi = analyze(2, reply_domain="d2.example", return_domain="d2.example", anomalies=(("high", "DMARC fail"),),
                        url_flags=(("URL shortener hides the real destination",),), when="Fri, 20 Nov 2026 22:00:00 +0000", **kw)                                                        # same IP, other time of day
        cors = [c for c in oi["correlations"] if c["scan_id"] == sid(1)]
        self.assertEqual(len(cors), 1)
        self.assertEqual((cors[0]["level"], cors[0]["correlation_type"]), ("insufficient", "shared_provider_only"))
        self.assertEqual(oi["findings"], [])

    def test_missing_attack_dna_data_degrades_to_the_graph_only(self):
        analyze(1, url="http://shared.example/login?a=1")
        r2 = scan(2, url="http://shared.example/login?a=2", ip="1.1.1.1")
        r2["campaign_fingerprint"], r2["campaign_matches"] = dna.find_matches(r2, history_sink=[])
        r2["evidence_register"], _ = ia.build_scan_evidence(r2)
        r2["entity_graph"] = eg.build_entity_graph(r2)
        r2.pop("campaign_matches")                                                  # Attack DNA output missing
        oi = op.build_operator_intel(r2)
        (c,) = oi["correlations"]
        self.assertEqual(oi["status"], "ok")
        self.assertNotIn("campaign_fingerprint", {s["category"] for s in c["signals"]})
        self.assertIn("shared_url", [s["code"] for s in c["signals"]])

    def test_missing_entity_graph_data_degrades_to_attack_dna_only_and_infrastructure_stays_unknown(self):
        analyze(1)
        r2 = scan(2, ip="1.1.1.1")
        r2["campaign_fingerprint"], r2["campaign_matches"] = dna.find_matches(r2, history_sink=[])
        r2["evidence_register"], _ = ia.build_scan_evidence(r2)
        r2["entity_graph"] = None
        oi = op.build_operator_intel(r2)
        c = next(x for x in oi["correlations"] if x["scan_id"] == sid(1))
        self.assertEqual(c["infrastructure"], "unknown")
        self.assertNotEqual(c["correlation_type"], "different_infrastructure")
        self.assertTrue(any("could not be compared" in x for x in c["limitations"]))

    def test_findings_are_traceable_and_every_reference_exists(self):
        analyze(1, url="http://shared.example/login?a=1")
        r2, oi = analyze(2, url="http://shared.example/login?a=2", ip="1.1.1.1", lat=SYDNEY[0], lon=SYDNEY[1], when="Fri, 20 Nov 2026 10:08:00 +0000")
        reg = {e["id"] for e in r2["evidence_register"]}
        self.assertTrue(oi["findings"])
        ids = [f["id"] for f in oi["findings"]]
        self.assertEqual(len(ids), len(set(ids)))
        for f in oi["findings"]:
            self.assertEqual(f["scan_id"], sid(2))
            self.assertTrue(f["evidence_ids"] and set(f["evidence_ids"]) <= reg, f["id"])
            self.assertTrue(all(h.startswith(sid(1) + ":S") for h in f["historical_refs"]))
            for key in ("kind", "correlation_type", "confidence", "explanation", "provenance", "limitations", "timestamps", "geo", "entities"):
                self.assertIn(key, f)
            self.assertTrue(f["limitations"])
            self.assertTrue(f["provenance"].startswith("operator_intel: deterministic"))
            self.assertIs(f["ai_generated"], False)

    def test_provenance_of_the_timestamp_evidence_is_preserved_as_an_untrusted_claim(self):
        r, _ = analyze(1)
        (t,) = [e for e in r["evidence_register"] if e["type"] == "timestamp"]
        self.assertEqual(t["origin"], "untrusted_claim")
        self.assertTrue(any("forged" in x for x in op.LIMITATIONS))

    def test_the_observation_is_stored_without_the_raw_ip_or_any_email_text(self):
        r, oi = analyze(1)
        rows = operator_rows(self.db)
        self.assertEqual(len(rows), 1)
        blob = repr(rows)
        self.assertNotIn("8.8.4.4", blob)
        self.assertNotIn("user1@", blob)
        self.assertNotIn("Invoice", blob)
        self.assertEqual(rows[0][0], sid(1))
        key = eg._e_session_key(sqlite3.connect(self.db))
        self.assertIn(eg._e_id(key, "ip", "8.8.4.4"), blob)                      # the HMAC id, under the Entity Graph's per-session key
        self.assertTrue(oi["stored"])

    def test_reprocessing_a_scan_replaces_its_observation_and_does_not_compare_it_with_itself(self):
        r, oi = analyze(1)
        again = op.build_operator_intel(r)
        self.assertEqual(len(operator_rows(self.db)), 1)
        self.assertEqual(again["correlations"], [])
        self.assertNotIn(sid(1), [c["scan_id"] for c in again["correlations"]])

    def test_the_result_and_the_scan_are_not_mutated(self):
        r, _ = analyze(1)
        before = copy.deepcopy(r)
        op.build_operator_intel(r)
        self.assertEqual(r, before)

    def test_the_output_is_json_serialisable(self):
        analyze(1, url="http://shared.example/login?a=1")
        _, oi = analyze(2, url="http://shared.example/login?a=2", ip="1.1.1.1", lat=SYDNEY[0], lon=SYDNEY[1], when="Fri, 20 Nov 2026 10:08:00 +0000")
        self.assertEqual(json.loads(json.dumps(oi))["status"], "ok")

    def test_the_summary_states_what_was_observed_what_is_related_and_what_is_uncertain(self):
        analyze(1, url="http://shared.example/login?a=1")
        _, oi = analyze(2, url="http://shared.example/login?a=2", ip="1.1.1.1")
        s = oi["summary"]
        self.assertTrue(s["observed"] and s["related"] and s["uncertain"])
        self.assertTrue(any("geolocated" in x for x in s["observed"]))
        self.assertTrue(any("not where a person is" in x.lower() or "infrastructure appears to be" in x for x in s["uncertain"]))

    def test_no_related_campaign_is_an_honest_empty_result_not_an_error(self):
        _, oi = analyze(1)
        self.assertEqual(oi["status"], "ok")
        self.assertEqual((oi["correlations"], oi["findings"]), ([], []))
        self.assertEqual(oi["journey"]["reasons"], ["no_related_observations"])
        self.assertTrue(any("No related campaign" in x for x in oi["summary"]["uncertain"]))


# ================================================================================================== fail-soft behaviour
class FailSoft(Base):
    def test_no_scan_identity_is_insufficient_evidence(self):
        for bad in (None, {}, [], "x", {"scan_id": "SC-1"}):
            oi = op.build_operator_intel(bad)
            self.assertEqual((oi["status"], oi["reason"]), ("insufficient_evidence", "no_scan_identity"))
            self.assertEqual((oi["correlations"], oi["findings"]), ([], []))

    def test_a_database_failure_is_reported_not_raised(self):
        with mock.patch.object(tracker, "get_connection", side_effect=RuntimeError("down")):
            oi = op.build_operator_intel(with_register(1))
        self.assertEqual((oi["status"], oi["reason"]), ("unavailable", "database_error"))
        self.assertEqual(oi["correlations"], [])
        self.assertIsNotNone(oi["event"])

    def test_an_unsaved_observation_is_reported_as_persistence_failed(self):
        with mock.patch.object(op, "_save_event", return_value=False):
            oi = op.build_operator_intel(with_register(1))
        self.assertEqual((oi["status"], oi["stored"], oi["reason"]), ("persistence_failed", False, "not_saved"))
        self.assertEqual(operator_rows(self.db) if os.path.exists(self.db) else [], [])
        self.assertEqual(op.status_message(oi)[0], "warning")

    def test_an_unexpected_error_is_a_status_not_an_exception(self):
        with mock.patch.object(op, "_candidates", side_effect=RuntimeError("boom")):
            oi = op.build_operator_intel(with_register(1))
        self.assertEqual((oi["status"], oi["reason"]), ("error", "unexpected"))

    def test_malformed_inputs_inside_a_real_result_never_raise(self):
        for mutate in (lambda r: r.update(campaign_matches="x"), lambda r: r.update(entity_graph=[1, 2]), lambda r: r.update(geo=None),
                       lambda r: r.update(origin_intel={"route": 5}), lambda r: r.update(evidence_register=[None, 5, {}]),
                       lambda r: r["geo"]["origin"].update(lat="x", lon=[]), lambda r: r.update(campaign_matches={"status": "ok", "matches": [None, 5, {"scan_id": 3}]})):
            r = with_register(1)
            mutate(r)
            oi = op.build_operator_intel(r)
            self.assertIn(oi["status"], ("ok", "persistence_failed", "insufficient_evidence"))

    def test_every_status_has_a_message_and_only_ok_is_silent(self):
        for st in ("persistence_failed", "insufficient_evidence", "unavailable", "error", "???"):
            level, text = op.status_message({"status": st})
            self.assertIn(level, ("warning", "error"))
            self.assertTrue(text)
            self.assertNotIn("nothing suspicious", text.lower())
        self.assertEqual(op.status_message({"status": "ok"}), ("ok", ""))
        self.assertEqual(op.status_message(None)[0], "warning")
        texts = [op.status_message({"status": s})[1] for s in ("persistence_failed", "insufficient_evidence", "unavailable", "error")]
        self.assertEqual(len(set(texts)), 4)


# ============================================================================================ isolation, privacy, boundaries
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


class SessionIsolation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patches = [mock.patch.object(tracker, "MULTIUSER", True), mock.patch.object(tracker, "SESSION_DIR", os.path.join(self.tmp.name, "sessions")),
                   mock.patch.object(tracker, "DB_FILE", os.path.join(self.tmp.name, "shared.db")), mock.patch.object(tracker, "_last_cleanup", 0.0),
                   fake_streamlit_runtime()]
        for p in patches:
            p.__enter__()
            self.addCleanup(p.__exit__, None, None, None)
        self.addCleanup(setattr, _CTX, "sid", None)

    def as_session(self, session, n, **kw):
        _CTX.sid = session
        return analyze(n, **kw)

    def test_another_session_sees_no_observation_and_no_related_campaign(self):
        self.as_session("A", 1)
        _, oi_b = self.as_session("B", 2)
        self.assertEqual((oi_b["correlations"], oi_b["findings"]), ([], []))
        for session, n in (("A", 1), ("B", 2)):
            _CTX.sid = session
            rows = operator_rows(tracker._db_path(False))
            self.assertEqual([r[0] for r in rows], [sid(n)])

    def test_the_same_session_correlates_and_a_different_one_cannot_reach_it(self):
        self.as_session("A", 1)
        _, oi = self.as_session("A", 2, ip="1.1.1.1")
        self.assertTrue(oi["correlations"])
        _, oi_c = self.as_session("C", 3, ip="9.9.9.9")
        self.assertEqual(oi_c["correlations"], [])

    def test_nothing_is_written_to_the_shared_database(self):
        self.as_session("A", 1)
        if os.path.exists(tracker.DB_FILE):
            conn = sqlite3.connect(tracker.DB_FILE)
            try:
                tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
            finally:
                conn.close()
            self.assertNotIn("operator_observations", tables)

    def test_without_an_identifiable_session_nothing_is_saved_and_it_is_reported(self):
        _CTX.sid = None
        _, oi = analyze(1)
        self.assertEqual((oi["status"], oi["stored"]), ("persistence_failed", False))
        self.assertFalse(os.path.isdir(tracker.SESSION_DIR) and os.listdir(tracker.SESSION_DIR))

    def test_deleting_a_visitors_data_removes_the_observations_too(self):
        self.as_session("A", 1)
        _CTX.sid = "A"
        self.assertTrue(tracker.delete_my_data())
        _, oi = self.as_session("A", 2, ip="1.1.1.1")
        self.assertEqual(oi["correlations"], [])


class BoundariesAndCompatibility(unittest.TestCase):
    def source(self, name):
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), name), encoding="utf-8") as f:
            return f.read()

    def test_the_module_makes_no_network_call_and_shares_nothing(self):
        src = self.source("operator_intel.py")
        for banned in ("import requests", "urllib.request", "urlopen", "import socket", "http.client", "import httpx", "aiohttp", "supabase",
                       "shared=True", "contribution", "feedback", "classifier", "nomic_embed", "import geolocate", "ipinfo", "os.environ", "subprocess"):
            self.assertNotIn(banned, src, banned)
        self.assertIn("get_connection(shared=False)", src)

    def test_no_protected_module_references_phase_5(self):
        for name in ("risk.py", "attack_dna.py", "correlate.py", "retro_hunt.py", "classifier.py", "tracker.py", "entity_graph.py", "origin_intel.py",
                     "geolocate.py", "campaign_intel.py", "contribution_client.py", "nomic_embed.py", "config.py"):
            self.assertNotIn("operator_intel", self.source(name), name)

    def test_the_analyzer_hook_is_fail_soft_and_never_changes_the_score(self):
        raw = b"From: a@example.com\r\nSubject: hi\r\n\r\nHello there, see http://evil.example/login for details.\r\n"
        db = _tmp_db(self)
        with mock.patch.object(tor_check, "maybe_update_tor_list", return_value=False):
            with mock.patch.object(analyzer, "operator_intel") as blocked:
                blocked.build_operator_intel.side_effect = RuntimeError("down")
                without = analyzer.analyze_email(raw, "a.eml")
            with_ = analyzer.analyze_email(raw, "a.eml")
        self.assertIsNone(without["operator_intel"])
        self.assertIn("operator_intel", with_)
        self.assertEqual((without["score"], without["level"]), (with_["score"], with_["level"]))
        self.assertEqual(without["evidence_register"], with_["evidence_register"])
        self.assertEqual(without["entity_graph"]["status"], with_["entity_graph"]["status"])

    def test_the_real_pipeline_attaches_a_status_dict(self):
        raw = b"From: a@example.com\r\nSubject: hi\r\n\r\nHello there.\r\n"
        db = _tmp_db(self)
        with mock.patch.object(tor_check, "maybe_update_tor_list", return_value=False):
            res = analyzer.analyze_email(raw, "a.eml")
        self.assertIn(res["operator_intel"]["status"], ("ok", "persistence_failed"))
        self.assertIn("journey", res["operator_intel"])



    def test_the_report_section_never_copies_other_scans_identifiers(self):
        db = _tmp_db(self)
        analyze(1, url="http://shared.example/login?a=1")
        r2, oi = analyze(2, url="http://shared.example/login?a=2", ip="1.1.1.1", lat=SYDNEY[0], lon=SYDNEY[1], when="Fri, 20 Nov 2026 10:08:00 +0000")
        r2["operator_intel"] = oi
        md = "\n".join(report.operator_intel_md(r2))
        self.assertIn("Phase 5", md)
        self.assertIn("Impossible journey", md)
        self.assertNotIn(sid(1), md)
        self.assertNotIn(sid(1)[3:], md)
        self.assertNotRegex(md, r"SC-[0-9a-f]{32}:S\d+")
        self.assertIn("Implausible", md)
        self.assertIn("not where a person is", md)
        self.assertNotIn("8.8.4.4", md)

    def test_the_report_states_failures_and_handles_missing_keys(self):
        self.assertEqual(report.operator_intel_md({}), [])
        md = "\n".join(report.operator_intel_md({"operator_intel": None}))
        self.assertIn("could not be computed", md)
        for status in ("unavailable", "error", "persistence_failed", "insufficient_evidence"):
            md = "\n".join(report.operator_intel_md({"operator_intel": {"status": status}}))
            self.assertIn("Phase 5", md)
            self.assertRegex(md, r"Analysis (unavailable|incomplete)")
        self.assertEqual(report.operator_intel_md({"operator_intel": {"status": "ok", "correlations": "x", "journey": 5, "event": [], "limitations": None}})[0][:4], "### ")

    def test_the_ui_panel_is_read_only_and_labels_evidence_kinds(self):
        src = self.source("app.py")
        start = src.index("# Phase 5: impossible-journey and common-operator analysis, precomputed by analyzer.py")
        panel = src[start:src.index("SHA-256 Cryptographic Evidence Hash", start)]
        self.assertIn('"operator_intel" in sel_res', panel)
        self.assertIn("operator_intel.status_message(", panel)
        self.assertIn("st.error", panel)
        self.assertIn("st.warning", panel)
        self.assertIn("[%s] %s", panel)                                            # signals are tagged [observed] / [inferred]
        self.assertIn("What remains uncertain", panel)
        for banned in ("build_operator_intel(", "get_connection(", "find_matches(", "requests", "urlopen", "shared=True"):
            self.assertNotIn(banned, panel)

    def test_the_phase_4_entity_graph_still_works_with_the_extra_origin_data(self):
        db = _tmp_db(self)
        r, _ = analyze(1)
        self.assertEqual(r["entity_graph"]["status"], "ok")
        self.assertTrue([e for e in r["entity_graph"]["edges"] if e["rel"] == "originated at"])


if __name__ == "__main__":
    unittest.main()
