#!/usr/bin/env python3
"""Anonymous access attack (simple model) - ANALYSIS ONLY.

Replay each baseline request with its session header(s) stripped out. If the
response still matches the original (authenticated) response hash, the
endpoint is reachable without auth -> vulnerable.

This module only implements the analysis contract expected by the
knumal-att4ck engine:

    build_attack_plan(record) -> dict
    evaluate(plan, attack_result, response_index) -> dict
        MUST include "current_resp_hash" in the returned dict -- it's a
        shared TSV column written by the engine for every attack model.

All operational concerns (sending requests, retries, adaptive thread pool,
progress bar, TSV writing) live in knumal-att4ck.py."""
import hashlib
import importlib.util
import json
import os
from typing import Any, Dict, List, Optional, Tuple

# knumal-att4ck.py sits three directories up from this file
_ENGINE_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "knumal-att4ck.py")


def _load_engine():
    """Import knumal-att4ck.py by path (its filename isn't a valid module name)."""

    spec = importlib.util.spec_from_file_location("knumal_att4ck", os.path.abspath(_ENGINE_PATH))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


engine = _load_engine()


# ==============================
# REQUEST PARSING / MUTATION
# ==============================

def parse_raw_request(raw_request: str) -> Tuple[Optional[str], Optional[str], Dict[str, str], str]:

    raw_request = (raw_request or "").replace("\r\n", "\n")
    lines = raw_request.split("\n")

    request_line = lines[0].strip() if lines else ""
    try:
        method, path, _ = request_line.split()
    except Exception:
        return None, None, {}, ""

    headers = {}
    body = ""
    is_body = False

    for line in lines[1:]:
        if is_body:
            body += line
            continue

        stripped = line.strip()
        if stripped == "":
            is_body = True
            continue

        if ":" in stripped:
            k, v = stripped.split(":", 1)
            headers[k.strip()] = v.strip()

    return method, path, headers, body


def strip_session_headers(headers: Dict[str, str], session_detected: List[Dict[str, str]]) -> Dict[str, str]:
    """Remove any header whose name (case-insensitive) appears in session_detected."""

    session_header_names = {k.lower() for entry in (session_detected or []) for k in entry.keys()}

    return {k: v for k, v in headers.items() if k.lower() not in session_header_names}


def build_url(record: Dict[str, Any], path: str) -> str:

    protocol = record.get("protocol", "https")
    host = record.get("host") or record.get("_host")
    port = record.get("port")

    default_port = {"https": "443", "http": "80"}.get(protocol)
    netloc = host if not port or port == default_port else f"{host}:{port}"

    return f"{protocol}://{netloc}{path}"


def build_curl_command(method: str, url: str, headers: Dict[str, str], body: str) -> str:
    """Build a one-line curl command (session headers already stripped) that
    can be copy-pasted straight into a terminal."""

    parts = ["curl", "-X", method, f"'{url}'"]

    for key, value in headers.items():
        if key.lower() in ("host", "content-length"):
            continue
        safe_value = value.replace("'", "'\\''")
        parts.append(f"-H '{key}: {safe_value}'")

    if body:
        safe_body = body.replace("'", "'\\''")
        parts.append(f"--data-raw '{safe_body}'")

    parts.append("--insecure")

    return " ".join(parts)


# ==============================
# HASHING / RESPONSE HELPERS
# ==============================

def hash_response_body(body: str) -> str:

    return hashlib.sha256(body.strip().encode(errors="ignore")).hexdigest()


def try_parse_json(text: str) -> Optional[Any]:

    try:
        return json.loads(text)
    except Exception:
        return None


# ==============================
# ANALYSIS CONTRACT (called by the engine)
# ==============================

def build_attack_plan(record: Dict[str, Any], extra_inputs: Dict[str, str]) -> Dict[str, Any]:
    """Precompute method/url/headers/body/curl for a record, once, before any attempt."""

    raw_request = record.get("request", "")
    session_detected = record.get("session_detected", [])
    method, path, headers, body = parse_raw_request(raw_request)

    stripped_headers = strip_session_headers(headers, session_detected)
    url = build_url(record, path) if path else ""
    curl_command = build_curl_command(method, url, stripped_headers, body) if method and path else ""

    return {
        "record": record,
        "method": method,
        "path": path,
        "url": url,
        "headers": stripped_headers,
        "body": body,
        "curl_command": curl_command,
    }


def get_extra_columns() -> List[str]:
    """This module has no attack-specific columns beyond the shared ones."""

    return []


def compute_response_similarity(baseline_body: str, replay_body: str):
    """Detect each body's content type first (json/xml/html/other), then
    compare structure only when both sides are a comparable, schema-bearing
    type (json vs json, xml vs xml, or html vs html). Returns "-" (not a
    number) when:
      - either side is empty/undetectable ("other"), or
      - the two sides ended up as different content types (e.g. baseline is
        json but the replay came back as an html error page) -- comparing a
        json schema against an html one isn't meaningful."""

    baseline_type = engine.detect_content_type_from_body(baseline_body)
    replay_type = engine.detect_content_type_from_body(replay_body)

    if baseline_type != replay_type:
        return "-"

    if baseline_type == "json":
        baseline_json = try_parse_json(baseline_body)
        replay_json = try_parse_json(replay_body)
        if baseline_json is None or replay_json is None:
            return "-"
        similarity, _, _ = engine.compare_structure(baseline_json, replay_json)
        return round(similarity, 2)

    if baseline_type == "xml":
        similarity, _, _ = engine.compare_structure_xml(baseline_body, replay_body)
        return round(similarity, 2)

    if baseline_type == "html":
        similarity, _, _ = engine.compare_structure_html(baseline_body, replay_body)
        return round(similarity, 2)

    # other: no meaningful schema to compare
    return "-"


def evaluate(plan: Dict[str, Any], attack_result: "engine.AttackResult", response_index: Dict[str, str],
             extra_inputs: Dict[str, str]) -> Dict[str, Any]:
    """Turn a successful AttackResult into the final VULNERABLE/UNAFFECTED/UNCERTAIN outcome.
    extra_inputs is unused here (anonymous attack needs no extra user input).

    - VULNERABLE: replay hash matches the authenticated baseline hash exactly.
    - UNCERTAIN: hashes differ, but the replay's http_status matches the
      baseline's authenticated http_status -- same HTTP-level outcome despite
      the body differing, so a plain hash compare can't tell; needs the LLM
      triage step (ambiguous/anonym_and_session_swap) to decide.
    - UNAFFECTED: hashes differ and http_status differs too (not "safe"/
      "clean" -- unaffected by THIS attack only; it may still be vulnerable
      to a different one)."""

    record = plan["record"]

    replay_hash = hash_response_body(attack_result.response_body)
    baseline_hash = record.get("knumal_resp")
    hash_matches = replay_hash == baseline_hash

    baseline_body = response_index.get(baseline_hash, "")
    similarity = compute_response_similarity(baseline_body, attack_result.response_body)

    # if hash_matches:
    #     result = "VULNERABLE"
    # elif similarity != "-" and similarity >= 80.0:
    #     result = "UNCERTAIN"
    # else:
    #     result = "UNAFFECTED"

    # UNCERTAIN is now decided by comparing the baseline's (authenticated)
    # http_status against the replay's live status code, instead of
    # response-structure similarity:
    #   - hash_matches (unchanged) -> VULNERABLE
    #   - hash differs, baseline http_status == current status code -> UNCERTAIN
    #     (same HTTP outcome as the authenticated baseline despite the body
    #     differing -- ambiguous, needs the LLM triage step to decide)
    #   - hash differs, http_status differs -> UNAFFECTED (the endpoint DID
    #     reject the anonymous request at the HTTP level)
    baseline_status = record.get("http_status", "")
    current_status = attack_result.status_code

    if hash_matches:
        result = "VULNERABLE"
    elif str(baseline_status) == str(current_status):
        result = "UNCERTAIN"
    else:
        result = "UNAFFECTED"

    endpoint = record.get("endpoint", "UNKNOWN")
    if result == "VULNERABLE":
        description = f"[VULNERABLE] {endpoint} - reachable without authentication (anonymous attack)"
    elif result == "UNCERTAIN":
        description = f"[UNCERTAIN] {endpoint} - response structure matches, hash differs (anonymous attack)"
    else:
        description = f"[UNAFFECTED] {endpoint} - blocked without authentication (anonymous attack)"

    return {
        "record": record,
        "curl_command": plan["curl_command"],
        "current_resp_data": attack_result.response_body,
        "current_resp_code": attack_result.status_code,
        "current_resp_hash": replay_hash,
        "response_similarity": similarity,
        "result": result,
        "description": description,
        "error": None,
    }
