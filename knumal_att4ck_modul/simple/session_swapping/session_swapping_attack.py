#!/usr/bin/env python3
"""Session swapping attack (simple model).

Pick one user (source_user, supplied via EXTRA_INPUTS in config.py) and take
the session header(s) knumal-0-browser.py detected for them
(record["session_detected"]). Replay every OTHER user's baseline request on
the same host, but with their own session header(s) swapped out for
source_user's session instead. If the response still looks like a normal,
authenticated success (same structure as that request's own authenticated
baseline, not an auth-error page), the endpoint is vulnerable to
session-swapping-based BAC -- source_user's session alone was enough to reach
another user's resource.

This module only implements the analysis contract expected by the
knumal-att4ck engine:

    build_attack_plan(record, extra_inputs) -> dict
    evaluate(plan, attack_result, response_index, extra_inputs) -> dict
        MUST include "current_resp_hash" in the returned dict -- it's a
        shared TSV column written by the engine for every attack model.

All operational concerns (sending requests, retries, adaptive thread pool,
progress bar, TSV writing) live in knumal-att4ck.py -- do not reimplement
them here."""
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
# SOURCE SESSION LOOKUP
# ==============================
#
# build_attack_plan() only receives ONE record at a time (see run_attacks() in
# the engine), so there's nowhere to look up "what session does source_user
# use on this host" from the records list alone. The engine's main() passes
# every record from the SAME baseline file the user picked (not filtered to
# the selected domain(s)) via extra_inputs["_all_baseline_records"] -- use
# THAT instead of re-loading a baseline file here. Re-loading independently
# (e.g. via find_baseline_files(".")[0], "newest file") is unsafe: if more
# than one baseline file exists, the newest one can silently be a DIFFERENT
# file than the one the user actually selected in main(), which then makes
# get_source_session() always return [] (this bit us in practice -- see
# session_swapping_design.md).

_source_session_cache: Dict[str, Dict[str, List[Dict[str, str]]]] = {}
_source_session_cache_key: Optional[int] = None


def _build_user_session_lookup(all_baseline_records: List[Dict[str, Any]]) -> Dict[str, Dict[str, List[Dict[str, str]]]]:
    """host -> user_login -> session_detected (from that user's own baseline records)."""

    lookup: Dict[str, Dict[str, List[Dict[str, str]]]] = {}
    for record in all_baseline_records:
        host = record.get("_host")
        user_login = record.get("_user_login")
        session_detected = record.get("session_detected")
        if not host or not user_login or not session_detected:
            continue
        lookup.setdefault(host, {})
        # Keep the first non-empty session_detected seen per user -- any
        # authenticated request from that user carries the same session.
        lookup[host].setdefault(user_login, session_detected)

    return lookup


def get_source_session(host: str, source_user: str, all_baseline_records: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Returns source_user's session_detected entries for `host`, or [] if
    not found (unknown user, or user never had a session detected on that host).

    Cached by id(all_baseline_records) so repeated calls across many
    build_attack_plan() invocations (one per record, run in parallel) don't
    rebuild the lookup table every time."""

    global _source_session_cache, _source_session_cache_key

    cache_key = id(all_baseline_records)
    if _source_session_cache_key != cache_key:
        _source_session_cache = _build_user_session_lookup(all_baseline_records)
        _source_session_cache_key = cache_key

    return _source_session_cache.get(host, {}).get(source_user, [])


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


def swap_session_headers(headers: Dict[str, str], session_detected: List[Dict[str, str]],
                          source_session: List[Dict[str, str]]) -> Dict[str, str]:
    """Remove the header owner's own session header(s) (named in
    session_detected) and replace them with source_session's values instead.

    Both session_detected and source_session share the same shape: a list of
    single-key dicts, e.g. [{"authorization": "Bearer ..."}] or
    [{"cookie": "session_id=..."}] (see knumal-0-browser.py /
    anonymous_attack.py's strip_session_headers() for the same shape)."""

    session_header_names = {k.lower() for entry in (session_detected or []) for k in entry.keys()}

    result = {k: v for k, v in headers.items() if k.lower() not in session_header_names}

    for entry in (source_session or []):
        for name, value in entry.items():
            result[name] = value

    return result


def build_url(record: Dict[str, Any], path: str) -> str:

    protocol = record.get("protocol", "https")
    host = record.get("host") or record.get("_host")
    port = record.get("port")

    default_port = {"https": "443", "http": "80"}.get(protocol)
    netloc = host if not port or port == default_port else f"{host}:{port}"

    return f"{protocol}://{netloc}{path}"


def build_curl_command(method: str, url: str, headers: Dict[str, str], body: str) -> str:
    """Build a one-line curl command (session headers already swapped) that
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


# ==============================
# PRE-ATTACK FILTER (called by the engine before any replay)
# ==============================

def filter_records(records: List[Dict[str, Any]], extra_inputs: Dict[str, str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Drop records whose knumal_req (request fingerprint: method+path+params)
    already appears among source_user's OWN baseline requests on the same
    host. The goal of session swapping is to test whether source_user's
    session grants access to a resource THEY DON'T already have -- if
    source_user already has an identical request in their own baseline, that
    endpoint is already known-accessible to them, so swapping their session
    into it isn't a meaningful BAC test."""

    source_user = extra_inputs.get("source_user", "")
    all_baseline_records = extra_inputs.get("_all_baseline_records", [])

    source_user_req_hashes_by_host: Dict[str, set] = {}
    for record in all_baseline_records:
        if record.get("_user_login") != source_user:
            continue
        host = record.get("_host", "")
        source_user_req_hashes_by_host.setdefault(host, set())
        source_user_req_hashes_by_host[host].add(record.get("knumal_req"))

    kept = []
    excluded = []
    for record in records:
        host = record.get("_host", "")
        knumal_req = record.get("knumal_req")
        already_has_access = knumal_req in source_user_req_hashes_by_host.get(host, set())

        if record.get("_user_login") != source_user and already_has_access:
            other_user = record.get("_user_login", "unknown")
            excluded.append({
                "record": record,
                "reason": f"source_user {source_user} already has access to this {other_user} endpoint (based on hash knumal_req) -- excluded",
            })
        else:
            kept.append(record)

    return kept, excluded


# ==============================
# ANALYSIS CONTRACT (called by the engine)
# ==============================

def build_attack_plan(record: Dict[str, Any], extra_inputs: Dict[str, str]) -> Dict[str, Any]:
    """Precompute method/url/headers/body/curl for a record, once, before any
    attempt. Swaps this record's own session for source_user's session on
    the same host -- if source_user has no session on this host (unknown
    user, or a host they never authenticated to), the request is left
    unswapped and will be skipped in evaluate() via a marked plan."""

    source_user = extra_inputs.get("source_user", "")
    host = record.get("_host", "")
    all_baseline_records = extra_inputs.get("_all_baseline_records", [])

    raw_request = record.get("request", "")
    session_detected = record.get("session_detected", [])
    method, path, headers, body = parse_raw_request(raw_request)

    source_session = get_source_session(host, source_user, all_baseline_records)
    is_source_user_record = record.get("_user_login") == source_user

    swapped_headers = headers
    if method and path and not is_source_user_record:
        swapped_headers = swap_session_headers(headers, session_detected, source_session)

    url = build_url(record, path) if path else ""
    curl_command = build_curl_command(method, url, swapped_headers, body) if method and path else ""

    return {
        "record": record,
        "method": method,
        "path": path,
        "url": url,
        "headers": swapped_headers,
        "body": body,
        "curl_command": curl_command,
        "source_user": source_user,
        "source_session_found": bool(source_session),
        "is_source_user_record": is_source_user_record,
    }


def get_extra_columns() -> List[str]:
    """This module reports which user's session was swapped in, alongside
    the shared columns."""

    return ["source_user"]


def evaluate(plan: Dict[str, Any], attack_result: "engine.AttackResult", response_index: Dict[str, str],
             extra_inputs: Dict[str, str]) -> Dict[str, Any]:
    """Turn a successful AttackResult into the final VULNERABLE/UNAFFECTED/UNCERTAIN outcome.

    Same classification rule as anonymous_attack.py, just with a swapped
    session instead of a stripped one:

    - VULNERABLE: replay hash matches the original owner's baseline hash
      exactly -- source_user's session was enough to reproduce the owner's
      exact response, i.e. reach the owner's resource using someone else's
      session.
    - UNCERTAIN: hashes differ, but the replay's http_status matches the
      original owner's authenticated http_status -- same HTTP-level outcome
      despite the body differing, so a plain hash compare can't tell; needs
      the LLM triage step (ambiguous/anonym_and_session_swap) to decide.
    - UNAFFECTED: hashes differ and http_status differs too (not "safe"/
      "clean" -- unaffected by THIS attack only; it may still be vulnerable
      to a different one).

    Records belonging to source_user itself are skipped (nothing to swap --
    it's already source_user's own request) and records where source_user
    has no known session on this host are skipped (nothing to swap in)."""

    record = plan["record"]
    endpoint = record.get("endpoint", "UNKNOWN")

    if plan.get("is_source_user_record"):
        result = "UNAFFECTED"
        description = f"[SKIPPED] {endpoint} - belongs to source_user itself, nothing to swap (session_swapping attack)"
        return {
            "record": record,
            "curl_command": plan["curl_command"],
            "current_resp_data": "",
            "current_resp_code": None,
            "current_resp_hash": "",
            "source_user": plan.get("source_user", ""),
            "response_similarity": "-",
            "result": result,
            "description": description,
            "error": None,
        }

    if not plan.get("source_session_found"):
        result = "UNAFFECTED"
        description = f"[SKIPPED] {endpoint} - source_user has no known session on this host (session_swapping attack)"
        return {
            "record": record,
            "curl_command": plan["curl_command"],
            "current_resp_data": "",
            "current_resp_code": None,
            "current_resp_hash": "",
            "source_user": plan.get("source_user", ""),
            "response_similarity": "-",
            "result": result,
            "description": description,
            "error": None,
        }

    replay_hash = hash_response_body(attack_result.response_body)
    baseline_hash = record.get("knumal_resp")
    hash_matches = replay_hash == baseline_hash

    baseline_body = response_index.get(baseline_hash, "")
    similarity = compute_response_similarity(baseline_body, attack_result.response_body)

    # if hash_matches:
    #     result = "VULNERABLE"
    # elif similarity != "-" and similarity >= 100.0:
    #     result = "UNCERTAIN"
    # else:
    #     result = "UNAFFECTED"

    # UNCERTAIN is now decided by comparing the baseline's (original owner's,
    # authenticated) http_status against the replay's live status code,
    # instead of response-structure similarity:
    #   - hash_matches (unchanged) -> VULNERABLE
    #   - hash differs, baseline http_status == current status code -> UNCERTAIN
    #     (same HTTP outcome as the owner's baseline despite the body
    #     differing -- ambiguous, needs the LLM triage step to decide)
    #   - hash differs, http_status differs -> UNAFFECTED (the endpoint DID
    #     reject the swapped session at the HTTP level)
    baseline_status = record.get("http_status", "")
    current_status = attack_result.status_code

    if hash_matches:
        result = "VULNERABLE"
    elif str(baseline_status) == str(current_status):
        result = "UNCERTAIN"
    else:
        result = "UNAFFECTED"

    source_user = plan.get("source_user", "")
    if result == "VULNERABLE":
        description = f"[VULNERABLE] {endpoint} - accessible using {source_user}'s session instead of the owner's (session_swapping attack)"
    elif result == "UNCERTAIN":
        description = f"[UNCERTAIN] {endpoint} - response structure matches, hash differs, using {source_user}'s session (session_swapping attack)"
    else:
        description = f"[UNAFFECTED] {endpoint} - {source_user}'s session was not accepted for this resource (session_swapping attack)"

    return {
        "record": record,
        "curl_command": plan["curl_command"],
        "current_resp_data": attack_result.response_body,
        "current_resp_code": attack_result.status_code,
        "current_resp_hash": replay_hash,
        "source_user": source_user,
        "response_similarity": similarity,
        "result": result,
        "description": description,
        "error": None,
    }
