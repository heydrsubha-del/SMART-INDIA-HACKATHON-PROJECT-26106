"""
SIH26106 - Local Ollama AI Threat Analysis

Uses Qwen3.5 0.8B locally through Ollama.
No external AI API key is required.
"""

import json
import os
import requests

from cloud_backend import BackendError, resolve_backend


OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
OLLAMA_TAGS_URL = "http://127.0.0.1:11434/api/tags"
OLLAMA_MODEL = "qwen3.5:0.8b"
OLLAMA_TIMEOUT = 600

GROQ_API_KEY_VAR = "SIH26106_GROQ_API_KEY"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
# llama-3.1-8b-instant (this file's original default) was decommissioned
# by Groq on 2026-08-16 for free/developer-tier keys and now 404s.
# openai/gpt-oss-20b is Groq's own documented 1:1 replacement for it.
# NOTE: gpt-oss models are "reasoning" models -- they spend part of the
# completion budget on hidden reasoning before emitting visible content,
# so num_predict/max_tokens needs enough headroom or the visible answer
# comes back empty. _groq_payload() below gives it a floor for this.
GROQ_MODEL = "openai/gpt-oss-20b"
# Local Ollama's 16K context comfortably takes a full 10-20 email batch in
# one request; Groq's cloud API enforces a much stricter request-body size
# limit and 413s well before that. Chunk cloud batch requests to stay
# under it -- see _analyze_batch_chunked().
CLOUD_BATCH_CHUNK_SIZE = 3


def _ollama_available(timeout=2):
    """True only when Ollama is reachable AND OLLAMA_MODEL is pulled."""
    try:
        response = requests.get(OLLAMA_TAGS_URL, timeout=timeout)
        response.raise_for_status()
        names = [str(m.get("name", "")) for m in response.json().get("models", [])]
        return any(n.split(":")[0] == OLLAMA_MODEL.split(":")[0] for n in names)
    except Exception:
        return False

# Leave one core free for the OS / the Streamlit process itself, but
# otherwise let Qwen use what's actually available rather than a
# hardcoded number picked without knowing the deployment machine.
_OLLAMA_THREADS = max(2, (os.cpu_count() or 4) - 1)



def _safe(value, default="Unknown"):
    if value is None or value == "":
        return default
    return value


# Qwen3.5:0.8b is a very small local model running with a bounded context
# window (see num_ctx in _base_payload). A phishing/spam message can carry
# dozens of URLs/domains/IPs; sending every one of them, uncapped, can push
# a single email's evidence past the context budget on its own. When that
# happens Ollama truncates from the *front* of the prompt -- which is
# exactly where the "how to write the report" instructions live -- so the
# model ends up looking only at a tail of raw JSON and just echoes it back
# instead of producing an analysis. Capping these lists keeps evidence
# dense but bounded for both single-email and batch prompts.
_MAX_IOC_LIST_ITEMS = 10


def _cap_list(values, limit=_MAX_IOC_LIST_ITEMS):
    if isinstance(values, list) and len(values) > limit:
        return values[:limit]
    return values


def _vpn_tor_evidence(origin, network_trust=None):
    """VPN/proxy/Tor evidence for the prompt, kept as its own explicit
    block (rather than buried inside origin_infrastructure) so Qwen can't
    skip over it. `origin` is result["geo"]["origin"], already available
    on every case. `network_trust` is the OPTIONAL dict app.py gets back
    from network_trust.assess_network_trust() for the email currently
    open in the Dossier -- passed in by the caller (never recomputed
    here) so this module doesn't need its own import of / dependency on
    network_trust.py, and the sender-history comparison it does only
    ever runs the one time the UI already runs it."""
    nt = network_trust or {}
    return {
        "vpn_or_proxy_masking_detected": bool(nt.get("is_anonymizing", False)),
        "anonymizing_infrastructure_type": _safe(
            nt.get("infra_display", origin.get("infra_label"))
        ),
        "tor_exit_node_confirmed": bool(origin.get("tor_exit_confirmed", False)),
        "tor_exit_confirmation_sources": _cap_list(origin.get("tor_exit_sources", []) or []),
        "network_trust_badge": _safe(nt.get("badge"), "Not evaluated for this run"),
        "network_trust_reasons": nt.get("reasons", []) or [],
    }


def build_evidence(result, network_trust=None):
    """
    Extract relevant forensic evidence from the
    existing SIH26106 analysis result.
    """

    parsed = result.get("parsed", {}) or {}
    headers = result.get("headers", {}) or {}
    iocs = result.get("iocs", {}) or {}
    geo = result.get("geo", {}) or {}
    ml = result.get("ml", {}) or {}
    intelligence = result.get("intelligence", {}) or {}
    verdict = result.get("verdict", {}) or {}

    origin = geo.get("origin", {}) or {}
    bec = headers.get("bec", {}) or {}

    body = (
        parsed.get("body_text")
        or parsed.get("full_text")
        or ""
    )

    # Keep the prompt small for CPU-based Qwen.
    body = str(body)[:5000]

    return {
        "email": {
            "from": _safe(parsed.get("from")),
            "reply_to": _safe(parsed.get("reply_to")),
            "subject": _safe(parsed.get("subject")),
            "body": body,
        },

        "machine_analysis": {
            "ml_phishing_probability": round(
                float(ml.get("prob", 0.0) or 0.0),
                4
            ),

            "ml_label": _safe(
                ml.get("label")
            ),

            "spf": _safe(
                headers.get("spf")
            ),

            "dkim": _safe(
                headers.get("dkim")
            ),

            "dmarc": _safe(
                headers.get("dmarc")
            ),

            "authentication_fail_score": float(
                headers.get(
                    "auth_fail_score",
                    0.0
                ) or 0.0
            ),

            "header_anomaly_score": float(
                headers.get(
                    "anomaly_score",
                    0.0
                ) or 0.0
            ),

            "header_anomalies": headers.get(
                "anomalies",
                []
            ),

            "bec_score": float(
                bec.get(
                    "score",
                    0.0
                ) or 0.0
            ),

            "bec_detected": bool(
                bec.get(
                    "is_bec",
                    False
                )
            ),

            "urls": _cap_list(iocs.get(
                "urls",
                []
            )),

            "suspicious_urls": _cap_list(iocs.get(
                "suspicious_urls",
                []
            )),

            "domains": _cap_list(iocs.get(
                "domains",
                []
            )),

            "ips": _cap_list(iocs.get(
                "ips",
                []
            )),

            "email_iocs": _cap_list(iocs.get(
                "emails",
                []
            )),

            "url_score": float(
                iocs.get(
                    "url_score",
                    0.0
                ) or 0.0
            ),

            "origin_ip": _safe(
                origin.get("ip")
            ),

            "origin_country": _safe(
                origin.get("country")
            ),

            "origin_infrastructure": _safe(
                origin.get("infra_label")
            ),

            "origin_risk": float(
                geo.get(
                    "origin_risk",
                    0.0
                ) or 0.0
            ),

            "urlhaus_matches": intelligence.get(
                "urlhaus_matches",
                0
            ),

            "local_memory_matches": intelligence.get(
                "local_memory_matches",
                0
            ),

            "risk_score": float(
                result.get(
                    "score",
                    0.0
                ) or 0.0
            ),

            "risk_level": _safe(
                result.get("level")
            ),

            "top_driver": _safe(
                verdict.get("top_driver")
            ),

            "vpn_tor_assessment": _vpn_tor_evidence(origin, network_trust),
        }
    }


def build_prompt(result, network_trust=None):
    """
    Build the prompt for single-email Qwen analysis.
    """

    evidence = build_evidence(result, network_trust=network_trust)

    return f"""

You are the local AI threat analyst of SIH26106.

Analyze the supplied email using ONLY the supplied
forensic evidence.

RULES:
- Never invent facts.
- Do not call an IP, URL, domain or sender malicious
  without supporting evidence.
- Do not recalculate the risk score if you do not have beneficial evidence to do so.
- Treat the existing risk score as evidence.
- Be compact but complete. Use the full available response budget.
- Prefer dense, evidence-backed detail over filler.
- Clearly distinguish evidence from interpretation.
- Use professional Markdown headings and numbered lists.
- Do not use ASCII art, repeated equals signs, dashed separator banners, or decorative horizontal lines.
- Do not put the report title inside the response; the application supplies the title.

Return a complete, report-ready assessment using EXACTLY these sections. Use dense technical detail and the full response budget without repeating the same point:

THREAT VERDICT:
2-3 sentences. State the overall threat disposition, the strongest evidence, and the practical implication.

ATTACK TYPE:
Choose ONE only: Phishing, Credential Phishing, Business Email Compromise, Executive Impersonation, Malicious Link, Malware Delivery, Spam, Low Risk, Unclear. Write ONLY the selected type.

CONFIDENCE:
Low, Medium, or High, followed by one short evidence-based reason.

KEY EVIDENCE:
Give 6-8 numbered evidence points. Include exact observed indicators where supplied, such as suspicious URLs, domains, IPs, authentication outcomes, header anomalies, sender/reply-to mismatch, and model findings.

ATTACKER OBJECTIVE:
Explain the likely objective in 2-3 sentences, distinguishing observation from inference.

THREAT ANALYSIS:
Write 2-4 compact paragraphs connecting the message content, social-engineering signals, technical indicators, authentication, and risk scoring evidence.

IOC & URL ASSESSMENT:
Discuss suspicious URLs, domains, IPs, look-alike indicators, URL risk signals, and any supplied threat-intelligence matches. Do not invent reputation data.

AUTHENTICATION & HEADER ASSESSMENT:
Explain SPF, DKIM, DMARC, header anomalies, BEC indicators, display-name/reply-to inconsistencies, and what the authentication result does or does not prove.

ORIGIN & INFRASTRUCTURE:
Summarize the supplied origin IP, country, route/hops, infrastructure classification, and origin risk. Clearly mark unknown fields.

VPN / TOR / ANONYMIZATION:
This section is MANDATORY and must never be skipped, even when nothing was
detected. Using ONLY the "vpn_tor_assessment" evidence block, state plainly:
(1) whether VPN/proxy masking was detected, and if so, the infrastructure
type named in the evidence; (2) whether the origin IP is a CONFIRMED Tor
exit node, and if so, cite the confirmation source(s) given; (3) the
network-trust badge and its reasons, if supplied. If nothing was detected,
say so explicitly (e.g. "No VPN, proxy, or Tor exit-node masking was
detected on this origin.") rather than omitting the section. Note that
detecting an exit node only confirms the LAST visible hop -- the true
originating IP behind an anonymizing network cannot be recovered from
this evidence.

RECOMMENDED ACTION:
Give 5 prioritized defensive actions, starting with the most urgent.

ANALYST NOTE:
A concise professional conclusion suitable for an incident record.

FORENSIC EVIDENCE:
Provide a compact technical summary of all important supplied findings, including the application's risk score and level, ML probability, BEC status, authentication, IOCs, origin infrastructure, VPN/Tor assessment, local memory matches, and URLhaus matches when present.

IMPORTANT:
- Use only supplied evidence.
- Never invent facts.
- Do not recalculate the risk score if you do not have beneficial evidence to do so.
- Keep the response report-ready.
- The VPN / TOR / ANONYMIZATION section is required in every report, even to report "not detected".

EVIDENCE:

{json.dumps(
    evidence,
    indent=2,
    ensure_ascii=False
)}

REMINDER: the evidence above is INPUT, not your answer. Do not copy, repeat,
or reformat the JSON. Write the full report now, starting with the
"THREAT VERDICT:" heading, using EXACTLY the sections listed earlier,
including "VPN / TOR / ANONYMIZATION" even when nothing was detected.
""".strip()


def _looks_like_dumped_evidence(answer, required_heading):
    """True if the model just echoed the evidence JSON back instead of
    writing the requested report.

    This is the failure mode that shows up when the prompt didn't fit the
    model's context window: the "write a report with these headings"
    instructions get truncated away and the model is left staring at raw
    JSON, so it reproduces it (or a fragment of it) verbatim. A real report
    always contains its required first heading; a dumped-evidence response
    never does but does contain our own JSON field names.
    """
    if required_heading.lower() in answer.lower():
        return False
    telltale_fields = ('"machine_analysis"', '"email":', '"evidence":', '"ml_phishing_probability"')
    return any(marker in answer for marker in telltale_fields)


def _request(payload, timeout=OLLAMA_TIMEOUT, required_heading=None, progress_callback=None):
    """Resolve local-vs-cloud backend, run one bounded streaming request,
    and normalize errors -- shared by the single-email and batch paths.

    Streams the response instead of waiting for a single non-streaming
    reply, so the progress bar keeps moving instead of sitting frozen
    right after "request sent" until the whole answer arrives. The
    progress-callback percentage math is identical for both backends;
    only the wire format differs (Ollama's raw NDJSON vs Groq's
    OpenAI-style SSE `data: {...}` lines), so that math lives once here
    and each backend has its own tiny line-parser.
    """
    try:
        backend, api_key = resolve_backend(
            local_available=_ollama_available(),
            env_var=GROQ_API_KEY_VAR,
            service_label="AI threat analysis",
        )
    except BackendError as exc:
        raise RuntimeError(str(exc))

    target_tokens = max(1, int((payload.get("options") or {}).get("num_predict", 700)))

    if backend == "cloud":
        answer = _stream_groq(payload, api_key, timeout, target_tokens, progress_callback)
    else:
        answer = _stream_ollama(payload, timeout, target_tokens, progress_callback)

    answer = answer.strip()
    if not answer:
        raise RuntimeError("The model returned an empty response.")
    if required_heading and _looks_like_dumped_evidence(answer, required_heading):
        raise RuntimeError(
            "The model returned raw evidence instead of a report — the prompt likely didn't fit "
            "its context window. Try again, or analyze fewer emails at once."
        )
    return answer


def _stream_ollama(payload, timeout, target_tokens, progress_callback):
    """Original local Ollama NDJSON streaming path -- unmoved."""
    stream_payload = dict(payload)
    stream_payload["stream"] = True

    answer = ""
    with requests.post(OLLAMA_URL, json=stream_payload, timeout=timeout, stream=True) as response:
        response.raise_for_status()
        tokens_seen = 0
        for line in response.iter_lines():
            if not line:
                continue
            try:
                chunk = json.loads(line)
            except ValueError:
                continue
            piece = (chunk.get("message") or {}).get("content", "")
            if piece:
                answer += piece
                tokens_seen += 1
                if progress_callback:
                    # Reserve 95-100% for the validation step below, and
                    # never claim 100% before the answer actually exists.
                    pct = 20 + min(75, int(75 * tokens_seen / target_tokens))
                    progress_callback(pct, f"Qwen is writing the report... ({tokens_seen} tokens)")
            if chunk.get("done"):
                break
    return answer


def _groq_payload(payload):
    """Translate our Ollama-shaped payload into Groq's OpenAI-style
    chat-completions body. build_evidence/build_prompt/_batch_prompt are
    all model-agnostic prompt engineering and need zero changes -- only
    the wire shape differs.

    openai/gpt-oss-20b is a reasoning model: it spends part of its token
    budget on hidden reasoning before any visible content, so a low
    max_tokens (fine for Ollama's non-reasoning Qwen) can come back with
    an empty visible answer here. reasoning_effort="low" keeps that
    hidden spend small, and max_tokens gets a floor with room for it."""
    options = payload.get("options") or {}
    requested_tokens = int(options.get("num_predict", 700))
    return {
        "model": GROQ_MODEL,
        "messages": payload.get("messages", []),
        "temperature": options.get("temperature", 0.1),
        "max_tokens": max(requested_tokens, 1024),
        "reasoning_effort": "low",
        "stream": True,
    }


def _stream_groq(payload, api_key, timeout, target_tokens, progress_callback):
    """Cloud fallback: Groq's OpenAI-style SSE stream (`data: {...}`
    lines, terminated by `data: [DONE]`) -- a different wire format from
    Ollama's raw NDJSON, but the same progress-percentage math applies."""
    groq_payload = _groq_payload(payload)
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    answer = ""
    with requests.post(GROQ_URL, headers=headers, json=groq_payload, timeout=timeout, stream=True) as response:
        response.raise_for_status()
        tokens_seen = 0
        for raw_line in response.iter_lines():
            if not raw_line:
                continue
            line = raw_line.decode("utf-8", errors="replace") if isinstance(raw_line, bytes) else raw_line
            if not line.startswith("data:"):
                continue
            data = line[len("data:"):].strip()
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except ValueError:
                continue
            choices = chunk.get("choices") or []
            if not choices:
                continue
            piece = (choices[0].get("delta") or {}).get("content", "")
            if piece:
                answer += piece
                tokens_seen += 1
                if progress_callback:
                    pct = 20 + min(75, int(75 * tokens_seen / target_tokens))
                    progress_callback(pct, f"Qwen is writing the report... ({tokens_seen} tokens)")
            if choices[0].get("finish_reason"):
                break
    return answer


def _base_payload(prompt):
    return {
        "model": OLLAMA_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a professional cybersecurity email-forensics "
                    "analyst. Be conservative, precise and evidence-driven."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "think": False,
        
        "keep_alive": "15m",
       
        "options": {
            "temperature": 0.1,
            # Was 700. The report gained a mandatory VPN/TOR/ANONYMIZATION
            # section on top of the existing ones; 700 tokens was already
            # tight for the original section list on a small CPU model, so
            # without headroom the new section would just push
            # "ANALYST NOTE" / "FORENSIC EVIDENCE" off the end instead of
            # actually adding coverage. Batch requests override this value
            # below with their own (much smaller) budget, so this only
            # affects the single-email report.
            "num_predict": 2500,
            "num_ctx": 16384, 
            "num_thread": _OLLAMA_THREADS,
            "num_batch": 8,
        },
    }


def analyze_with_ollama(result, timeout=OLLAMA_TIMEOUT, progress_callback=None, network_trust=None):
    """Analyze one forensic result using local Ollama/Qwen.

    `network_trust` is optional: pass the dict app.py already gets back
    from network_trust.assess_network_trust() for this email (badge,
    is_anonymizing, infra_display, reasons) so the report's VPN/TOR
    section can cite it. Safe to omit -- the report still covers the
    Tor-exit-list confirmation and infra classification that are already
    part of `result` either way."""
    try:
        if progress_callback:
            progress_callback(5, "Preparing evidence for Qwen...")
        payload = _base_payload(build_prompt(result, network_trust=network_trust))
        if progress_callback:
            progress_callback(20, "Qwen request sent...")
        answer = _request(payload, timeout=timeout, required_heading="THREAT VERDICT", progress_callback=progress_callback)
        if progress_callback:
            progress_callback(100, "Qwen analysis complete")
        return {"ok": True, "model": OLLAMA_MODEL, "analysis": answer}
    except requests.exceptions.ConnectionError:
        return {"ok": False, "error": "Ollama is not running. Start Ollama and try again."}
    except requests.exceptions.Timeout:
        return {"ok": False, "error": "Ollama analysis timed out. The local model may be busy."}
    except requests.exceptions.HTTPError as exc:
        return {"ok": False, "error": f"Ollama HTTP error: {exc}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _batch_prompt(batch_items):
    """Build a compact one-request prompt for the newest emails."""
    compact = []
    for item in batch_items:
        result = item.get("result", {}) or {}
        evidence = build_evidence(result)

        # Keep batch prompts compact so 20 emails remain practical on CPU.
        email = evidence.get("email", {}) or {}
        machine = evidence.get("machine_analysis", {}) or {}

        email["body"] = str(email.get("body", ""))[:1400]

        # Tighter cap than the single-email path: this evidence gets
        # multiplied by up to 20 items in one prompt, so a few extra IOCs
        # per email adds up fast against the model's context budget.
        for key in (
            "urls",
            "suspicious_urls",
            "domains",
            "ips",
            "email_iocs",
        ):
            machine[key] = _cap_list(machine.get(key), limit=5)

        vpn_tor = machine.get("vpn_tor_assessment") or {}
        if isinstance(vpn_tor.get("tor_exit_confirmation_sources"), list):
            vpn_tor["tor_exit_confirmation_sources"] = _cap_list(
                vpn_tor["tor_exit_confirmation_sources"], limit=3
            )

        compact.append({
            "position": item.get("position"),
            "row": item.get("row"),
            "date": item.get("date"),
            "evidence": evidence,
        })

    count = len(compact)
    positions = ", ".join(f"#{c['position']}" for c in compact)
    last_position = compact[-1]["position"] if compact else 1
    return f"""
You are the SIH26106 local email-threat analyst.
This batch contains {count} INDEPENDENT emails, numbered {positions}.
Use only the supplied evidence and never invent facts.
Do not recalculate the application's risk_score or risk_level for any
email — use the ones already given in its evidence exactly as they are.
Never blend senders, URLs, or wording from one email into another email's
line, even if two emails look related or come from the same platform.

Return ONLY the section below — no other headings, no long paragraphs,
nothing before or after it:

PER-EMAIL SUMMARY:
Cover every one of the {count} emails, #1 through #{last_position}, in
order — every email number must appear exactly once somewhere in this
section. Keep it extremely short: group 2 or more emails into ONE entry
ONLY when they share the same risk_level AND the same one-line
recommendation; otherwise give each email its own entry. Each entry is
EXACTLY 3 short lines — no extra sentences, no extra blank lines between
entries:
Email #<number(s)> — Verdict: <risk_level in upper case>
Action: <under 8 words, e.g. "Do not click links" or "No action needed">
Recommendation: <under 12 words, from that email's own evidence only>

Example of two entries (for format only — do not reuse this content):
Email #1 — Verdict: HIGH
Action: Do not click any links.
Recommendation: Report to IT and delete the email.

Email #2, #4 — Verdict: LOW
Action: No action needed.
Recommendation: Safe routine notification, no follow-up required.

EMAIL EVIDENCE:
{json.dumps(compact, indent=2, ensure_ascii=False)}

REMINDER: the evidence above is INPUT, not your answer. Do not copy, repeat,
or reformat the JSON. Write your answer now, starting with the
"PER-EMAIL SUMMARY:" heading. Every one of the {count} email numbers
({positions}) must appear somewhere in it, each entry exactly 3 lines long.
""".strip()


def analyze_batch_with_ollama(batch_items, timeout=OLLAMA_TIMEOUT, progress_callback=None):
    """Analyze a small recent-email batch in one local Qwen request, or
    (on the cloud backend) several smaller chunked Groq requests stitched
    back into one combined report.

    Local Ollama's 16K context window comfortably takes all N emails in a
    single request; Groq's cloud API enforces a much stricter request-body
    size limit and 413s on a full 10-20 email batch. So on cloud we split
    into chunks of CLOUD_BATCH_CHUNK_SIZE emails, run _batch_prompt/
    _request per chunk (each chunk is itself a valid, self-contained
    "N INDEPENDENT emails" batch prompt -- the numbering logic in
    _batch_prompt already works on any subset), and concatenate their
    PER-EMAIL SUMMARY entries into one final answer with a single heading.
    """
    if not batch_items:
        return {"ok": False, "error": "No emails were supplied for Qwen analysis."}
    try:
        if progress_callback:
            progress_callback(5, "Preparing batch evidence...")

        try:
            backend, _ = resolve_backend(
                local_available=_ollama_available(),
                env_var=GROQ_API_KEY_VAR,
                service_label="AI threat analysis",
            )
        except BackendError as exc:
            return {"ok": False, "error": str(exc)}

        if backend == "cloud" and len(batch_items) > CLOUD_BATCH_CHUNK_SIZE:
            answer = _analyze_batch_chunked(batch_items, timeout=timeout, progress_callback=progress_callback)
        else:
            payload = _base_payload(_batch_prompt(batch_items))
            # Each entry is now capped at 3 short lines (~25-30 tokens), so even
            # an un-grouped 20-email batch fits well under 1,000 tokens. Keeping
            # this modest also makes CPU generation noticeably faster than the
            # old multi-section report.
            payload["options"]["num_predict"] = min(1400, 350 + 45 * len(batch_items))
            if progress_callback:
                progress_callback(25, "Qwen is analyzing the selected emails...")
            answer = _request(payload, timeout=timeout, required_heading="PER-EMAIL SUMMARY", progress_callback=progress_callback)

        if progress_callback:
            progress_callback(100, "Qwen batch analysis complete")
        return {
            "ok": True,
            "model": OLLAMA_MODEL if backend == "local" else GROQ_MODEL,
            "analysis": answer,
            "count": len(batch_items),
        }
    except requests.exceptions.ConnectionError:
        return {"ok": False, "error": "Ollama is not running. Start Ollama and try again."}
    except requests.exceptions.Timeout:
        return {"ok": False, "error": "Qwen batch analysis timed out. Try 10 emails instead of 20."}
    except requests.exceptions.HTTPError as exc:
        return {"ok": False, "error": f"Ollama HTTP error: {exc}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _split_per_email_summary(answer, required_heading="PER-EMAIL SUMMARY"):
    """Return just the entry lines under the heading, dropping the
    heading itself and anything before/after -- used when stitching
    several chunk answers into one combined report."""
    lower = answer.lower()
    idx = lower.find(required_heading.lower())
    if idx == -1:
        return answer.strip()
    body = answer[idx + len(required_heading):]
    return body.lstrip(":").strip()


def _analyze_batch_chunked(batch_items, timeout, progress_callback):
    """Cloud-only path: run the batch in CLOUD_BATCH_CHUNK_SIZE-sized
    chunks (each a normal, self-contained _batch_prompt/_request call)
    and stitch the PER-EMAIL SUMMARY entries back into one answer."""
    chunks = [
        batch_items[i:i + CLOUD_BATCH_CHUNK_SIZE]
        for i in range(0, len(batch_items), CLOUD_BATCH_CHUNK_SIZE)
    ]
    total = len(chunks)
    sections = []
    for i, chunk in enumerate(chunks):
        chunk_start_pct = int(20 + 70 * i / total)
        chunk_end_pct = int(20 + 70 * (i + 1) / total)

        def _chunk_cb(pct, message, _start=chunk_start_pct, _end=chunk_end_pct, _i=i, _total=total):
            if progress_callback:
                scaled = _start + (pct / 100.0) * (_end - _start)
                progress_callback(int(scaled), f"Qwen (part {_i + 1}/{_total}): {message}")

        payload = _base_payload(_batch_prompt(chunk))
        payload["options"]["num_predict"] = min(1400, 350 + 45 * len(chunk))
        answer = _request(payload, timeout=timeout, required_heading="PER-EMAIL SUMMARY", progress_callback=_chunk_cb)
        sections.append(_split_per_email_summary(answer))

    return "PER-EMAIL SUMMARY:\n" + "\n\n".join(sections)