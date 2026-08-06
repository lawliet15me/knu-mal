#!/usr/bin/env python3
"""Parameter mutation fuzzing attack (simple model) - ANALYSIS ONLY.

Object-level substitution (IDOR/BOLA): replay each "simple"-classified
baseline request with the SAME authenticated session, but with one numeric
parameter (path segment, query string value, or JSON/form body field)
mutated to another value. If the response comes back structurally identical
to a normal, authenticated response but with different data, the endpoint is
leaking another user's object through that parameter.

Two mutation strategies are combined for each numeric parameter (see
get_reference_values() and generate_fuzz_values()):
  - sweep: +/-fuzz_range nearby integers around the baseline value (may or
    may not correspond to a real object).
  - reference (BACFuzz-inspired, see paper/dharmaadi -bacfuzz.pdf Section
    4.2.3): real values observed for that SAME parameter key on OTHER
    users' baseline requests -- guaranteed to point at an object that
    actually exists, rather than hoping a nearby-integer guess lands on one.

Unlike anonymous_attack.py / session_swapping_attack.py, this module does
NOT keep a strict 1 baseline record -> 1 HTTP request mapping: a single
record can have several independent numeric parameters, and each one is
fuzzed across a range of nearby values. Since knumal-att4ck.py's engine calls
build_attack_plan() exactly once per item in the list it's given, the
fan-out (1 record -> N parameters x R fuzz values -> many attempts) happens
inside filter_records() instead, which the engine already allows to freely
reshape the records list it receives (see apply_pre_attack_filter() in the
engine) before run_attacks() ever starts. filter_records() here returns one
SYNTHETIC "attempt record" per (parameter, fuzz value) combination -- a
shallow copy of the original baseline record with just its `request` text
rewritten to carry the mutated value, tagged with _fuzz_param/_fuzz_original/
_fuzz_mutated. `knumal_req`/`knumal_resp` are deliberately left pointing at
the ORIGINAL baseline record's hashes (not recomputed for the mutated
request) so the response_similarity lookup still resolves against the true,
unmutated baseline response.

This module only implements the analysis contract expected by the
knumal-att4ck engine:

    filter_records(records, extra_inputs) -> (kept, excluded)
        Restricts to classification=="simple" records that have at least one
        fuzzable numeric parameter, THEN expands each into one attempt record
        per (parameter, fuzz value) pair.
    build_attack_plan(record, extra_inputs) -> dict
    evaluate(plan, attack_result, response_index, extra_inputs) -> dict
        MUST include "current_resp_hash" in the returned dict -- it's a
        shared TSV column written by the engine for every attack model.
    get_extra_columns() -> List[str]
        Reports fuzz_param/fuzz_original_value/fuzz_mutated_value so each
        VULNERABLE row's TSV entry shows exactly which parameter and value
        proved exploitable.

All operational concerns (sending requests, retries, adaptive thread pool,
progress bar, TSV writing) live in knumal-att4ck.py -- do not reimplement
them here."""
import hashlib
import importlib.util
import json
import os
import random
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode

# knumal-att4ck.py sits three directories up from this file
_ENGINE_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "knumal-att4ck.py")


def _load_engine():
    """Import knumal-att4ck.py by path (its filename isn't a valid module name)."""

    spec = importlib.util.spec_from_file_location("knumal_att4ck", os.path.abspath(_ENGINE_PATH))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


engine = _load_engine()

DEFAULT_FUZZ_RANGE = 1


# ==============================
# REQUEST PARSING (shared with anonymous_attack.py's approach)
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


def build_url(record: Dict[str, Any], path: str) -> str:

    protocol = record.get("protocol", "https")
    host = record.get("host") or record.get("_host")
    port = record.get("port")

    default_port = {"https": "443", "http": "80"}.get(protocol)
    netloc = host if not port or port == default_port else f"{host}:{port}"

    return f"{protocol}://{netloc}{path}"


def refresh_session_headers(headers: Dict[str, str], session_detected: List[Dict[str, str]]) -> Dict[str, str]:
    """Replace the session header(s) captured in the record's raw `request`
    text (a snapshot from whenever knumal-0-browser.py/knumal-1-read-xml.py
    ran) with the CURRENT session_detected values knumal-3-baseline.py looked
    up at baseline-replay time (record["_user"]["domains"][].session --
    see get_session_headers_for_host() there).

    These two are NOT guaranteed to match: session_detected is refreshed
    every time the baseline pipeline re-authenticates, so a raw request
    captured earlier can carry an already-expired JWT (confirmed in practice
    -- the same record's request Authorization header and session_detected
    entry decoded to different `iat`/`exp` timestamps for the same user).
    Sending a mutated request with a stale token risks a 401 that has
    nothing to do with the parameter mutation itself, silently under-
    reporting VULNERABLE endpoints. This mirrors strip_session_headers() in
    anonymous_attack.py and swap_session_headers() in
    session_swapping_attack.py, except here the session is refreshed to the
    SAME user's current one -- neither stripped (anonymous) nor swapped to
    another user (session_swapping), since object-level substitution must
    keep the requester's own valid identity and only mutate the object
    reference."""

    session_header_names = {k.lower() for entry in (session_detected or []) for k in entry.keys()}

    result = {k: v for k, v in headers.items() if k.lower() not in session_header_names}

    for entry in (session_detected or []):
        for name, value in entry.items():
            result[name] = value

    return result


def build_curl_command(method: str, url: str, headers: Dict[str, str], body: str) -> str:
    """Build a one-line curl command that can be copy-pasted straight into a terminal."""

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
# PARAMETER DISCOVERY
# ==============================
#
# Three independent sources of a numeric parameter, checked separately since
# a record can carry more than one at once (e.g. a numeric path segment AND
# a numeric body field on the same request):
#   - path   : trailing numeric segment(s) in the URL path, e.g. ".../1"
#   - query  : a query-string key whose value is purely digits, e.g. "?id=5"
#   - body   : a JSON or urlencoded-form field whose value is purely digits
#              (only checked when Content-Type on the REQUEST itself is
#              exactly "application/json" or "application/x-www-form-urlencoded";
#              any other/missing Content-Type -- including plain GET requests
#              with no body -- skips body parsing entirely, though path/query
#              are still checked independently of method or Content-Type)

_PURE_DIGITS_RE = re.compile(r"^\d+$")
_TRAILING_PATH_NUMBER_RE = re.compile(r"/(\d+)(?=$|\?)")


def _is_pure_digits(value: Any) -> bool:
    """True for a JSON integer, or a string containing only digits (covers
    both "the ID happens to be typed as a number" and "the ID happens to be
    typed as a string that only contains digits" -- both are fuzz candidates
    per the module's design; a value containing any letter is left alone)."""

    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    if isinstance(value, str):
        return bool(_PURE_DIGITS_RE.match(value.strip()))
    return False


def get_request_content_type(headers: Dict[str, str]) -> Optional[str]:
    """Reads the Content-Type header off the REQUEST itself (not the
    precomputed record["content-type"] field, which reflects the response).
    Returns the media-type portion only (charset/boundary parameters
    stripped), or None if no Content-Type header is present at all."""

    for key, value in headers.items():
        if key.lower() == "content-type":
            return value.split(";", 1)[0].strip().lower()
    return None


def find_path_params(path: str) -> List[Tuple[str, str, int]]:
    """Returns a list of (param_id, value, start_index) for every trailing
    numeric path segment. param_id is a stable label ("path[0]", "path[1]", ...)
    used later to target exactly this occurrence during mutation, since a
    path could in principle carry more than one numeric segment."""

    path_only = path.split("?", 1)[0]
    found = []
    for i, match in enumerate(re.finditer(r"/(\d+)(?=/|$)", path_only)):
        found.append((f"path[{i}]", match.group(1), match.start(1)))
    return found


def find_query_params(path: str) -> List[Tuple[str, str, str]]:
    """Returns a list of (param_id, key, value) for every query-string key
    whose value is purely digits. param_id is "query:<key>"."""

    if "?" not in path:
        return []
    query_string = path.split("?", 1)[1]
    found = []
    for key, value in parse_qsl(query_string, keep_blank_values=True):
        if _is_pure_digits(value):
            found.append((f"query:{key}", key, value))
    return found


def find_body_params_json(body: str) -> List[Tuple[str, str, Any]]:
    """Returns a list of (param_id, key, value) for every TOP-LEVEL JSON
    field whose value is purely digits. Nested objects/arrays are not
    descended into -- the ground-truth dataset this module targets (see
    project memory) only seeds identifiers as top-level fields."""

    parsed = try_parse_json(body)
    if not isinstance(parsed, dict):
        return []

    found = []
    for key, value in parsed.items():
        if _is_pure_digits(value):
            found.append((f"body:{key}", key, value))
    return found


def find_body_params_form(body: str) -> List[Tuple[str, str, str]]:
    """Same as find_body_params_json() but for
    application/x-www-form-urlencoded bodies (key=value&key2=value2)."""

    found = []
    for key, value in parse_qsl(body, keep_blank_values=True):
        if _is_pure_digits(value):
            found.append((f"body:{key}", key, value))
    return found


def discover_fuzz_candidates(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Returns every fuzzable numeric parameter found in this record's raw
    request, tagged with enough info to mutate just that one occurrence:
    {"param_id", "source" ("path"/"query"/"body"), "key", "value"}."""

    raw_request = record.get("request", "")
    method, path, headers, body = parse_raw_request(raw_request)
    if not method or not path:
        return []

    candidates = []

    for param_id, value, _start in find_path_params(path):
        candidates.append({"param_id": param_id, "source": "path", "key": param_id, "value": value})

    for param_id, key, value in find_query_params(path):
        candidates.append({"param_id": param_id, "source": "query", "key": key, "value": value})

    content_type = get_request_content_type(headers)
    if content_type == "application/json":
        for param_id, key, value in find_body_params_json(body):
            candidates.append({"param_id": param_id, "source": "body_json", "key": key, "value": value})
    elif content_type == "application/x-www-form-urlencoded":
        for param_id, key, value in find_body_params_form(body):
            candidates.append({"param_id": param_id, "source": "body_form", "key": key, "value": value})
    # Any other Content-Type (or none -- e.g. a plain GET with no body) skips
    # body parsing entirely; path/query candidates above are unaffected.

    return candidates


# ==============================
# FUZZ VALUE GENERATION
# ==============================

def generate_fuzz_values(base_value: int, fuzz_range: int) -> List[int]:
    """Positive-only fuzz values around base_value, e.g. base=5, range=10 ->
    [1,2,3,4,6,7,8,9,10,11,12,13,14,15] (0 and negatives are floored out,
    base_value itself is excluded since mutating a parameter to its own
    value isn't a mutation)."""

    low = max(1, base_value - fuzz_range)
    high = base_value + fuzz_range

    return [v for v in range(low, high + 1) if v != base_value]


# ==============================
# REFERENCE MUTATION (BACFuzz-inspired -- see paper/dharmaadi -bacfuzz.pdf
# Section 4.2.3 "Mutation")
# ==============================
#
# In addition to the +/-N sweep above, also try values that are KNOWN to be
# real, valid identifiers because they were observed as this SAME parameter
# key on a DIFFERENT user's baseline request. This is a stronger signal than
# a plain nearby-integer guess: a reference value is guaranteed to point at
# an object that actually exists in the system (owned by another user),
# rather than hoping a +/-N guess happens to land on someone's real ID. Built
# from extra_inputs["_all_baseline_records"] -- every record from the SAME
# baseline file the user selected in main() (see knumal-att4ck.py's docstring
# on that key, and session_swapping_attack.py for the established pattern of
# using it for cross-record lookups instead of re-loading a baseline file).

_reference_value_cache: Dict[int, Dict[str, List[int]]] = {}


def _build_reference_value_index(all_baseline_records: List[Dict[str, Any]]) -> Dict[str, List[int]]:
    """key -> sorted list of distinct integer values seen for that parameter
    key (path[N] / query:name / body:name) across ALL baseline records,
    regardless of which user or endpoint they came from. Cached by
    id(all_baseline_records) so it's built once per attack run, not once per
    record (mirrors session_swapping_attack.py's _source_session_cache)."""

    index: Dict[str, set] = {}
    for record in all_baseline_records:
        if record.get("classification") != "simple":
            continue
        for candidate in discover_fuzz_candidates(record):
            try:
                value = int(candidate["value"])
            except ValueError:
                continue
            index.setdefault(candidate["key"], set()).add(value)

    return {key: sorted(values) for key, values in index.items()}


def get_reference_values(key: str, base_value: int, all_baseline_records: List[Dict[str, Any]]) -> List[int]:
    """Returns every distinct real value observed for this parameter `key`
    across the whole baseline (any user, any endpoint), excluding
    base_value itself. Empty list if the key was never seen elsewhere or
    `all_baseline_records` wasn't provided."""

    if not all_baseline_records:
        return []

    cache_key = id(all_baseline_records)
    if cache_key not in _reference_value_cache:
        _reference_value_cache[cache_key] = _build_reference_value_index(all_baseline_records)

    values = _reference_value_cache[cache_key].get(key, [])
    return [v for v in values if v != base_value]


# ==============================
# REQUEST MUTATION
# ==============================

def _mutate_path(path: str, param_id: str, mutated_value: str) -> str:
    """param_id is "path[N]" -- rewrite the Nth trailing numeric path segment."""

    index = int(param_id[len("path["):-1])
    path_part, _, query_part = path.partition("?")

    occurrences = list(re.finditer(r"/(\d+)(?=/|$)", path_part))
    if index >= len(occurrences):
        return path

    match = occurrences[index]
    new_path_part = path_part[:match.start(1)] + mutated_value + path_part[match.end(1):]

    return new_path_part + ("?" + query_part if query_part else "")


def _mutate_query(path: str, key: str, mutated_value: str) -> str:

    path_part, _, query_part = path.partition("?")
    pairs = parse_qsl(query_part, keep_blank_values=True)
    new_pairs = [(k, mutated_value if k == key else v) for k, v in pairs]

    return f"{path_part}?{urlencode(new_pairs)}"


def _mutate_body_json(body: str, key: str, mutated_value: int) -> str:

    parsed = try_parse_json(body)
    if not isinstance(parsed, dict) or key not in parsed:
        return body

    # Preserve the original field's type (int vs digit-string) so the
    # mutated request stays schema-consistent with the baseline.
    if isinstance(parsed[key], str):
        parsed[key] = str(mutated_value)
    else:
        parsed[key] = mutated_value

    return json.dumps(parsed)


def _mutate_body_form(body: str, key: str, mutated_value: int) -> str:

    pairs = parse_qsl(body, keep_blank_values=True)
    new_pairs = [(k, str(mutated_value) if k == key else v) for k, v in pairs]

    return urlencode(new_pairs)


def build_mutated_request(raw_request: str, candidate: Dict[str, Any], mutated_value: int) -> Optional[str]:
    """Returns a full raw HTTP request string with exactly ONE parameter
    occurrence mutated (path segment, query value, or body field), all other
    parts of the request left byte-for-byte identical to the baseline.
    Returns None if the request couldn't be re-parsed (malformed)."""

    raw_request_norm = (raw_request or "").replace("\r\n", "\n")
    lines = raw_request_norm.split("\n")
    if not lines:
        return None

    request_line = lines[0]
    try:
        method, path, http_version = request_line.split()
    except Exception:
        return None

    source = candidate["source"]
    mutated_str = str(mutated_value)

    if source == "path":
        new_path = _mutate_path(path, candidate["param_id"], mutated_str)
    elif source == "query":
        new_path = _mutate_query(path, candidate["key"], mutated_str)
    else:
        new_path = path

    header_end = next((i for i, line in enumerate(lines[1:], start=1) if line.strip() == ""), len(lines))
    header_lines = lines[1:header_end]
    body = "\n".join(lines[header_end + 1:]) if header_end < len(lines) else ""

    if source == "body_json":
        body = _mutate_body_json(body, candidate["key"], mutated_value)
    elif source == "body_form":
        body = _mutate_body_form(body, candidate["key"], mutated_value)

    new_request_line = f"{method} {new_path} {http_version}"
    new_lines = [new_request_line] + header_lines + [""] + ([body] if body else [""])

    return "\r\n".join(new_lines)


# ==============================
# ANALYSIS CONTRACT (called by the engine)
# ==============================

# Records with classification=="ambiguous" are never sent an HTTP request by
# this module (see evaluate()'s docstring for why: their response is known
# to contain volatile fields, so hash AND structural-Jaccard comparison are
# both unreliable oracles for them). They still need to appear in the TSV
# with result=UNCERTAIN so the endpoint isn't silently missing from the
# output -- but run_attacks() only ever calls build_attack_plan()/evaluate()
# for items filter_records() puts in `kept`, and those two functions have no
# way to fabricate a result without ever calling send_request(). Instead,
# filter_records() stashes these records here (module-level, populated once
# per attack run) and aggregate_outcomes() -- called by the engine AFTER
# run_attacks() finishes, see knumal-att4ck.py's main() -- synthesizes one
# UNCERTAIN summary row per stashed record and appends it to the final
# outcome list, without ever sending a request for it.
_last_ambiguous_records: List[Dict[str, Any]] = []


def filter_records(records: List[Dict[str, Any]], extra_inputs: Dict[str, str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Two-stage pre-attack filter, unlike the exclude-only filters in
    anonymous_attack.py / session_swapping_attack.py:

      1. Restrict to classification=="simple" records that have at least one
         fuzzable numeric parameter (path/query/body). classification=="ambiguous"
         records are stashed in _last_ambiguous_records (see its comment above)
         instead of being dropped silently -- aggregate_outcomes() turns them
         into UNCERTAIN summary rows after run_attacks() finishes.
      2. EXPAND each surviving record into one synthetic "attempt record" per
         (parameter, fuzz value) combination -- this is where the 1-record-
         becomes-many-requests fan-out happens, since knumal-att4ck.py's
         engine calls build_attack_plan() exactly once per item it's given
         (see this module's docstring for why this is done here rather than
         in the engine itself)."""

    global _last_ambiguous_records
    _last_ambiguous_records = []

    try:
        fuzz_range = int(extra_inputs.get("fuzz_range", "").strip())
    except (ValueError, AttributeError):
        fuzz_range = DEFAULT_FUZZ_RANGE
    if fuzz_range < 1:
        fuzz_range = DEFAULT_FUZZ_RANGE

    all_baseline_records = extra_inputs.get("_all_baseline_records", [])

    kept: List[Dict[str, Any]] = []
    excluded: List[Dict[str, Any]] = []

    for record in records:
        if record.get("classification") != "simple":
            if record.get("classification") == "ambiguous":
                _last_ambiguous_records.append(record)
            excluded.append({"record": record, "reason": "not classification=simple -- excluded from parameter mutation fuzzing"})
            continue

        candidates = discover_fuzz_candidates(record)
        if not candidates:
            excluded.append({"record": record, "reason": "no numeric path/query/body parameter found -- excluded from parameter mutation fuzzing"})
            continue

        raw_request = record.get("request", "")
        attempts_for_record = 0

        for candidate in candidates:
            try:
                base_value = int(candidate["value"])
            except ValueError:
                continue

            # Two mutation strategies, combined and de-duplicated:
            #   - sweep: +/-fuzz_range nearby integers (may or may not exist)
            #   - reference: real values seen for this exact parameter key on
            #     OTHER users' baseline requests (guaranteed to exist) --
            #     BACFuzz-style reference mutation, see get_reference_values()
            sweep_values = generate_fuzz_values(base_value, fuzz_range)
            reference_values = get_reference_values(candidate["key"], base_value, all_baseline_records)

            mutation_plan = [(v, "sweep") for v in sweep_values]
            mutation_plan += [(v, "reference") for v in reference_values if v not in sweep_values]

            for mutated_value, mutation_kind in mutation_plan:
                mutated_request = build_mutated_request(raw_request, candidate, mutated_value)
                if mutated_request is None:
                    continue

                attempt_record = dict(record)
                attempt_record["request"] = mutated_request
                attempt_record["_fuzz_param_id"] = candidate["param_id"]
                attempt_record["_fuzz_source"] = candidate["source"]
                attempt_record["_fuzz_key"] = candidate["key"]
                attempt_record["_fuzz_original_value"] = candidate["value"]
                attempt_record["_fuzz_mutated_value"] = mutated_value
                attempt_record["_fuzz_mutation_kind"] = mutation_kind

                kept.append(attempt_record)
                attempts_for_record += 1

        if attempts_for_record == 0:
            excluded.append({"record": record, "reason": "numeric parameter(s) found but none produced a valid mutated request -- excluded from parameter mutation fuzzing"})

    return kept, excluded


def build_attack_plan(record: Dict[str, Any], extra_inputs: Dict[str, str]) -> Dict[str, Any]:
    """record here is a synthetic attempt record produced by filter_records()
    above -- its "request" field already carries the mutated parameter value.
    The session header(s) are refreshed to record["session_detected"] (the
    SAME user's current session, see refresh_session_headers()) rather than
    left as whatever the raw captured request happened to carry -- only the
    object identifier changes, the requester's own identity does not."""

    raw_request = record.get("request", "")
    method, path, headers, body = parse_raw_request(raw_request)
    session_detected = record.get("session_detected", [])
    headers = refresh_session_headers(headers, session_detected)

    url = build_url(record, path) if path else ""
    curl_command = build_curl_command(method, url, headers, body) if method and path else ""

    return {
        "record": record,
        "method": method,
        "path": path,
        "url": url,
        "headers": headers,
        "body": body,
        "curl_command": curl_command,
    }


def get_extra_columns() -> List[str]:
    """This module reports one row per ENDPOINT (not per attempt) after
    aggregate_outcomes() collapses every (parameter, fuzz value) attempt back
    down -- see that function's docstring. The per-attempt fuzz_* fields are
    computed inside evaluate() but never written to the TSV directly; only
    the two aggregated columns below are:
      - parameter_affected: "key=value,key2=value2" -- one sample value per
        parameter PROVEN vulnerable for this endpoint (empty if none).
      - value_test: "key=min-max,key2=min-max" -- the full range of values
        actually attempted for each fuzzable parameter on this endpoint,
        regardless of outcome (documents test coverage)."""

    return ["parameter_affected", "value_test"]


def compute_response_similarity(baseline_body: str, replay_body: str):
    """Same schema-only comparison as anonymous_attack.py: detect content
    type first, then compare structure (not values) so that "same shape,
    different data" -- the classic IDOR signature -- registers as a
    similarity of 100 even though the hash differs."""

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

    return "-"


def evaluate(plan: Dict[str, Any], attack_result: "engine.AttackResult", response_index: Dict[str, str],
             extra_inputs: Dict[str, str]) -> Dict[str, Any]:
    """Turn a successful AttackResult into VULNERABLE/UNAFFECTED for one
    (parameter, fuzz value) attempt.

    - VULNERABLE: hash differs from baseline (mutating the parameter DID
      change what came back -- ruling out "server ignored the mutation and
      returned my own data unchanged") AND the response is structurally a
      100% schema match against the baseline (same shape, different data --
      the classic IDOR signature illustrated in this module's docstring).
      Decided immediately, no LLM escalation -- consistent with every other
      "simple" model attack module's hash-first, no-UNCERTAIN-bucket design
      for this attack (there is no ambiguous/parameter_mutation_fuzzing
      triage step; a partial structural match here is treated as a clean
      rejection, not an ambiguous case, since object-level substitution
      responses are expected to be either a full schema match or a
      structurally distinct error/rejection body).
    - UNAFFECTED: hash matches baseline (server ignored the mutation and
      returned the requester's own object unchanged) OR the response is
      NOT a full structural match (rejected/error response, different
      shape)."""

    record = plan["record"]
    endpoint = record.get("endpoint", "UNKNOWN")

    replay_hash = hash_response_body(attack_result.response_body)
    baseline_hash = record.get("knumal_resp")
    hash_matches = replay_hash == baseline_hash

    baseline_body = response_index.get(baseline_hash, "")
    similarity = compute_response_similarity(baseline_body, attack_result.response_body)

    if not hash_matches and similarity != "-" and similarity >= 100.0:
        result = "VULNERABLE"
    else:
        result = "UNAFFECTED"

    fuzz_source = record.get("_fuzz_source", "")
    fuzz_key = record.get("_fuzz_key", "")
    fuzz_original = record.get("_fuzz_original_value", "")
    fuzz_mutated = record.get("_fuzz_mutated_value", "")
    fuzz_mutation_kind = record.get("_fuzz_mutation_kind", "")

    if result == "VULNERABLE":
        description = (f"[VULNERABLE] {endpoint} - {fuzz_key} ({fuzz_source}, {fuzz_mutation_kind}) "
                        f"{fuzz_original} -> {fuzz_mutated} returned another user's object "
                        f"(parameter mutation fuzzing)")
    else:
        description = (f"[UNAFFECTED] {endpoint} - {fuzz_key} ({fuzz_source}, {fuzz_mutation_kind}) "
                        f"{fuzz_original} -> {fuzz_mutated} rejected or unchanged "
                        f"(parameter mutation fuzzing)")

    return {
        "record": record,
        "curl_command": plan["curl_command"],
        "current_resp_data": attack_result.response_body,
        "current_resp_code": attack_result.status_code,
        "current_resp_hash": replay_hash,
        # fuzz_* fields are consumed by aggregate_outcomes() to build the
        # per-endpoint parameter_affected/value_test columns -- they are NOT
        # TSV columns themselves (see get_extra_columns()).
        "fuzz_source": fuzz_source,
        "fuzz_key": fuzz_key,
        "fuzz_original_value": fuzz_original,
        "fuzz_mutated_value": fuzz_mutated,
        "fuzz_mutation_kind": fuzz_mutation_kind,
        "response_similarity": similarity,
        "result": result,
        "description": description,
        "error": None,
    }


# ==============================
# POST-RUN AGGREGATION (optional engine hook, see knumal-att4ck.py's main())
# ==============================
#
# filter_records() fanned each baseline endpoint out into many (parameter,
# fuzz value) attempt outcomes -- an endpoint with, say, 2 numeric parameters
# produces several rows on its own. This collapses that back down to
# EXACTLY ONE row per original endpoint (identified by knumal_req, which
# every attempt record kept pointing at the true baseline record -- see
# filter_records()'s docstring):
#   - parameter_affected: "key=value,key2=value2" -- one sample value per
#     parameter PROVEN vulnerable on this endpoint (picked at random among
#     that parameter's vulnerable attempts if more than one qualified value
#     was found). Empty string if no parameter proved vulnerable.
#   - value_test: "key=min-max,key2=min-max" -- for EVERY fuzzable
#     parameter on this endpoint (vulnerable or not), the full min-max range
#     of values actually attempted, documenting test coverage.
#   - current_req (curl_command): one curl command per parameter listed in
#     parameter_affected, using that parameter's sampled vulnerable value,
#     joined by newlines -- if nothing was vulnerable, falls back to the
#     first attempt's curl command (same as before).
#   - result: VULNERABLE if parameter_affected is non-empty, else UNAFFECTED.
#
# It also appends one UNCERTAIN summary row per classification=="ambiguous"
# endpoint stashed by filter_records() into _last_ambiguous_records -- these
# never had an HTTP request sent (see that variable's comment), so their
# outcome dict has no real AttackResult to draw from: current_resp_hash,
# current_resp_code, current_req, parameter_affected, and value_test are all
# left empty, mirroring how session_swapping_attack.py's evaluate() marks
# its own never-requested is_source_user_record rows (empty current_resp_code
# is the established convention across this codebase for "no HTTP request
# sent").

def _format_value_test(min_v: int, max_v: int) -> str:
    """"min-max", or just "min" when only one value was tried for that key."""

    return str(min_v) if min_v == max_v else f"{min_v}-{max_v}"


def _build_ambiguous_uncertain_row(record: Dict[str, Any]) -> Dict[str, Any]:

    endpoint = record.get("endpoint", "UNKNOWN")
    description = (f"[UNCERTAIN] {endpoint} - classification=ambiguous, response contains "
                    f"volatile fields, out of scope for rule-based parameter mutation fuzzing "
                    f"(no request sent)")

    return {
        "record": record,
        "curl_command": "",
        "current_resp_data": "",
        "current_resp_code": "",
        "current_resp_hash": "",
        "parameter_affected": "",
        "value_test": "",
        "response_similarity": "-",
        "result": "UNCERTAIN",
        "description": description,
        "error": None,
    }


def _build_endpoint_summary_row(attempts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """attempts: every (parameter, fuzz value) outcome for ONE endpoint."""

    endpoint = attempts[0]["record"].get("endpoint", "UNKNOWN")

    by_key: Dict[str, List[Dict[str, Any]]] = {}
    for attempt in attempts:
        by_key.setdefault(attempt["fuzz_key"], []).append(attempt)

    parameter_affected_parts = []
    curl_commands = []

    for key, key_attempts in by_key.items():
        vulnerable = [a for a in key_attempts if a["result"] == "VULNERABLE"]
        if not vulnerable:
            continue
        chosen = random.choice(vulnerable)
        parameter_affected_parts.append(f"{key}={chosen['fuzz_mutated_value']}")
        curl_commands.append(chosen["curl_command"])

    value_test_parts = []
    for key, key_attempts in by_key.items():
        values = [int(a["fuzz_mutated_value"]) for a in key_attempts]
        value_test_parts.append(f"{key}={_format_value_test(min(values), max(values))}")

    is_vulnerable = bool(parameter_affected_parts)
    result = "VULNERABLE" if is_vulnerable else "UNAFFECTED"
    parameter_affected = ",".join(parameter_affected_parts)
    value_test = ",".join(value_test_parts)
    curl_command = "\n".join(curl_commands) if curl_commands else attempts[0]["curl_command"]

    if is_vulnerable:
        description = (f"[VULNERABLE] {endpoint} - parameter(s) {parameter_affected} returned "
                        f"another user's object (parameter mutation fuzzing)")
    else:
        description = (f"[UNAFFECTED] {endpoint} - {len(attempts)} parameter mutation attempt(s) "
                        f"tried ({value_test}), none returned another user's object "
                        f"(parameter mutation fuzzing)")

    summary = dict(attempts[0])
    summary["curl_command"] = curl_command
    summary["parameter_affected"] = parameter_affected
    summary["value_test"] = value_test
    summary["result"] = result
    summary["description"] = description

    return summary


def aggregate_outcomes(completed_outcomes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

    by_endpoint: Dict[str, List[Dict[str, Any]]] = {}
    order: List[str] = []

    for outcome in completed_outcomes:
        endpoint_key = outcome["record"].get("knumal_req", "")
        if endpoint_key not in by_endpoint:
            by_endpoint[endpoint_key] = []
            order.append(endpoint_key)
        by_endpoint[endpoint_key].append(outcome)

    aggregated: List[Dict[str, Any]] = []

    for endpoint_key in order:
        aggregated.append(_build_endpoint_summary_row(by_endpoint[endpoint_key]))

    for record in _last_ambiguous_records:
        aggregated.append(_build_ambiguous_uncertain_row(record))

    return aggregated
