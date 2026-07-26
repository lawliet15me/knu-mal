#!/usr/bin/env python3
"""Parameter mutation fuzzing attack (ambiguous model) - ANALYSIS ONLY.

Object-level substitution (IDOR/BOLA) for classification=="ambiguous"
endpoints -- the ones simple/parameter_mutation_fuzzing_attack.py deliberately
skips (see that module's docstring) because their response body carries
volatile fields (tokens/timestamps/signatures), which makes hash comparison
AND schema-only Jaccard structural comparison both unreliable oracles: a
volatile field changes the hash/schema on every request regardless of
whether the underlying DATA is the same or belongs to a different user.

This module replays the SAME mutation strategy as the "simple" counterpart
(sweep +/-fuzz_range around each numeric parameter's baseline value, plus
BACFuzz-style reference mutation using real values seen on other users'
requests -- see get_reference_values()), but replaces the oracle: instead of
comparing response SCHEMAS, it uses a two-stage oracle (structural pre-check
+ LLM-discovered identity-field diff, see the "TWO-STAGE ORACLE" comment
block below) to judge whether the mutated response's DATA content matches
the baseline's data content closely enough to be the same underlying record
(i.e., another user's object leaked through the identifier substitution).

NOTE (v3 of this module -- see parameter_mutation_fuzzing_attack.py.old for
the pre-LLM deterministic-heuristic version): asking the LLM to judge
identity/similarity DIRECTLY (per-attempt, over the full response bodies)
was tried in FIVE independent prompt designs across this module's history
(four documented in parameter_mutation_fuzzing_attack.py.old, plus one more
categorical A/B/C/D variant tried in this version) and failed all five,
including on clear-cut real endpoint data (two structurally-identical
responses for two obviously different real people). The failure mode was
consistent: the model cannot reliably perform an end-to-end "are these the
same person" judgment over a full JSON body, regardless of framing.

This version keeps the field-diff HEURISTIC from the .old version (Stage 2
itself is deterministic Python again, not an LLM call per attempt) but
removes its single remaining weakness: IDENTITY_FIELD_KEYWORDS used to be a
hardcoded, static, English-centric tuple with no automated discovery
process (see project memory). Now the LLM is used for a much narrower,
one-shot-per-BASELINE task it is actually suited for -- reading ONE sample
response body for a given endpoint and naming which of ITS OWN field names
are identity-bearing (see discover_identity_fields_by_llm() below) -- instead
of judging identity/similarity across two responses per attempt. The result
is cached per endpoint (by knumal_resp/baseline hash) so the LLM is called
once per distinct baseline body, not once per mutation attempt; the
deterministic field-diff comparison (classify_data_identity_by_field_diff())
then runs exactly as before, just against a per-endpoint discovered field
list instead of the static hardcoded one.

Unlike ambiguous/anonym_and_session_swap_llm.py, this is NOT a TSV
post-processor -- simple/parameter_mutation_fuzzing_attack.py never sends a
request for classification=="ambiguous" endpoints in the first place (there
is no existing response to re-judge), so this module implements the full
replay contract itself (filter_records/build_attack_plan/evaluate), just
like simple/parameter_mutation_fuzzing_attack.py does, with the request
mutation/discovery helpers copied verbatim from that module (see project
memory on copying reusable parsing/hashing helpers rather than re-deriving
them) and only the oracle (evaluate()) and the per-endpoint aggregation
swapped out.

This module only implements the analysis contract expected by the
knumal-att4ck engine:

    filter_records(records, extra_inputs) -> (kept, excluded)
        Restricts to classification=="ambiguous" records that have at least
        one fuzzable numeric parameter, THEN expands each into one attempt
        record per (parameter, fuzz value) pair.
    build_attack_plan(record, extra_inputs) -> dict
    evaluate(plan, attack_result, response_index, extra_inputs) -> dict
        MUST include "current_resp_hash" in the returned dict -- it's a
        shared TSV column written by the engine for every attack model.
    get_extra_columns() -> List[str]
        Reports parameter_affected/value_test (one row per endpoint, see
        aggregate_outcomes()).

All operational concerns (sending requests, retries, adaptive thread pool,
progress bar, TSV writing) live in knumal-att4ck.py -- do not reimplement
them here."""
import hashlib
import importlib.util
import json
import os
import random
import re
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode

# knumal-att4ck.py sits three directories up from this file; tools/ is a
# sibling of knumal-att4ck.py at that same level.
_BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..")
_ENGINE_PATH = os.path.join(_BASE_DIR, "knumal-att4ck.py")
_LLMCLASS_PATH = os.path.join(_BASE_DIR, "tools", "llm_classifier.py")


def _load_module(path: str, name: str):
    """Import a module by path (filenames with dashes aren't valid module names)."""

    spec = importlib.util.spec_from_file_location(name, os.path.abspath(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


engine = _load_module(_ENGINE_PATH, "knumal_att4ck")
llmclass_tools = _load_module(_LLMCLASS_PATH, "llm_classifier_pmf")

DEFAULT_FUZZ_RANGE = 1
# "both" keeps the original +id/-id two-sided sweep available for other
# runs; a run can instead ask for "up" (base+1..base+fuzz_range only) or
# "down" (base-fuzz_range..base-1 only) via the sweep_direction extra_input
# in config.py -- see generate_fuzz_values()'s docstring.
DEFAULT_SWEEP_DIRECTION = "both"
MODEL = "qwen2.5:3b"


# ==============================
# TWO-STAGE ORACLE: structural pre-check, THEN LLM-discovered identity-field
# diff (heuristic comparison, LLM only used ONCE per baseline to name fields)
# ==============================
#
# Stage 2 is a deterministic Python field-diff heuristic again (same
# comparison logic as parameter_mutation_fuzzing_attack.py.old), but
# IDENTITY_FIELD_KEYWORDS's role -- a static, hardcoded, English-centric
# tuple with no discovery process -- is replaced by a per-BASELINE LLM call:
# discover_identity_fields_by_llm() shows Qwen2.5:3B ONE sample response body
# (the baseline for a given endpoint) and asks it to name which of THAT
# body's own top-level field names identify a specific person/record (name,
# email, employee id, address, ...) as opposed to volatile/non-identity
# fields (tokens, timestamps, hashes, booleans, counters). This is a much
# narrower task than the five failed direct-judgment prompts (see module
# docstring): the model only has to read field NAMES in ONE known-good
# document and label them, never compare two responses or judge whether two
# people are "the same," which is the specific task it repeatedly failed at.
#
# The discovered field-name set is cached per distinct baseline body (keyed
# by knumal_resp hash) so the LLM runs once per endpoint, not once per
# mutation attempt -- classify_data_identity_by_field_diff() then does the
# actual per-attempt comparison purely in Python against that cached set,
# exactly like the .old heuristic did against the static keyword tuple.

_identity_field_cache: Dict[str, Tuple[str, ...]] = {}


def build_identity_field_discovery_prompt(sample_body: str) -> str:
    """Asks the LLM to read ONE response body and name its own identity-
    bearing top-level field names -- a field-labeling task over a single
    known document, not a cross-response identity judgment (see the
    TWO-STAGE ORACLE comment block above for why this task shape was
    chosen)."""

    return (
        f"Here is one example JSON response body from an API endpoint:\n{sample_body}\n\n"
        "List the top-level field names in this JSON whose VALUE reveals "
        "who a SPECIFIC person is -- e.g. a person's name, email, phone "
        "number, physical address, national ID/NIK/KTP, employee ID, "
        "username, date of birth, salary, bank account number, job "
        "position/department, or similar personally-identifying data.\n\n"
        "EXCLUDE every field whose value does NOT by itself tell you which "
        "person this is -- this includes tokens, hashes, signatures, "
        "random/opaque strings, timestamps, dates that aren't a birth "
        "date, booleans, numeric status/counter fields, and any field "
        "whose NAME suggests it is technical/volatile rather than "
        "personal (e.g. names containing \"token\", \"hash\", \"dynamic\", "
        "\"signature\", \"stamp\", \"cache\", \"id\" that is a database "
        "row id rather than a person's own ID number, \"status\", "
        "\"success\", \"code\"). A company/organization name (e.g. "
        "employer name) is NOT a personal identity field either, since "
        "many different people can share the same employer.\n\n"
        "When unsure whether a field is personally-identifying, EXCLUDE "
        "it -- only include fields you are confident single out one "
        "specific person.\n\n"
        "Answer with exactly one line in this exact format, a "
        "comma-separated list of the field names only (no explanation), "
        "or NONE if there are no identity-bearing fields:\n"
        "FIELDS: name, email, address"
    )


def parse_identity_field_list(raw: str) -> Tuple[str, ...]:
    """Extracts the comma-separated field-name list from
    build_identity_field_discovery_prompt()'s expected response format.
    Falls back to treating the whole line after a "FIELDS:" label (or the
    whole raw response if the label is missing) as the list. Returns an
    empty tuple for "NONE" or an unparseable response."""

    match = re.search(r"FIELDS:\s*(.+)", raw, re.IGNORECASE)
    line = match.group(1) if match else raw

    line = line.strip()
    if not line or line.upper().startswith("NONE"):
        return ()

    fields = [part.strip().strip('"').strip("'").lower() for part in line.split(",")]
    return tuple(field for field in fields if field)


def discover_identity_fields_by_llm(baseline_hash: str, baseline_body: str) -> Tuple[str, ...]:
    """Returns the cached (or newly discovered) tuple of identity-bearing
    field NAMES for this baseline, used by is_identity_field() in place of
    the static IDENTITY_FIELD_KEYWORDS tuple. One LLM call per distinct
    baseline_hash, cached for the lifetime of the process -- NOT one call
    per mutation attempt (see TWO-STAGE ORACLE comment block above).
    Falls back to the static IDENTITY_FIELD_KEYWORDS tuple if the LLM call
    or parse fails, so a transient Ollama error doesn't silently disable
    Stage 2 for that endpoint."""

    if baseline_hash in _identity_field_cache:
        return _identity_field_cache[baseline_hash]

    prompt = build_identity_field_discovery_prompt(baseline_body)
    raw = llmclass_tools.call_ollama(MODEL, prompt)

    fields = parse_identity_field_list(raw) if raw is not None else ()
    if not fields:
        fields = IDENTITY_FIELD_KEYWORDS

    _identity_field_cache[baseline_hash] = fields
    return fields


# Fallback keyword list, used only when the per-baseline LLM discovery call
# fails outright (see discover_identity_fields_by_llm()) -- kept from
# parameter_mutation_fuzzing_attack.py.old as a safety net, not the primary
# source of identity-field names anymore.
IDENTITY_FIELD_KEYWORDS = (
    "name", "email", "phone", "address", "nik", "ktp", "employee_id",
    "userid", "user_id", "username", "dob", "birth", "salary", "gaji",
    "rekening", "account_number", "npwp", "position", "jabatan",
    "department", "departemen",
)


def flatten_json(obj: Any, prefix: str = "") -> Dict[str, Any]:
    """Dotted-path -> scalar value map for a parsed JSON object/array
    (arrays are indexed numerically in the path, e.g. "items[0].name")."""

    items: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            child_path = f"{prefix}.{key}" if prefix else key
            items.update(flatten_json(value, child_path))
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            items.update(flatten_json(value, f"{prefix}[{i}]"))
    else:
        items[prefix] = obj
    return items


def is_identity_field(field_path: str, identity_fields: Tuple[str, ...]) -> bool:
    """True if the last path segment's name suggests it identifies a
    specific person/record, based on the given identity_fields tuple
    (per-baseline LLM-discovered field names, see
    discover_identity_fields_by_llm()). Case-insensitive substring match on
    the field's own name (not the full path), e.g. "attributes.email" ->
    checks "email"."""

    field_name = field_path.rsplit(".", 1)[-1].lower()
    return any(keyword in field_name for keyword in identity_fields)


def classify_data_identity_by_field_diff(baseline_body: str, current_body: str,
                                          identity_fields: Tuple[str, ...]) -> Tuple[str, Optional[int], Optional[int]]:
    """Returns (result, similarity_score, confidence_score) with the SAME
    vocabulary llmclass_tools.classify_with_llm() uses ("vulnerable_by_llm" /
    "unaffected_by_llm" / "llm_error") for drop-in use in evaluate() below --
    the comparison itself is deterministic Python, not an LLM call.
    similarity_score here is a diagnostic count (number of changed
    identity-bearing fields), not a model-produced confidence value.
    identity_fields is the per-baseline field-name tuple discovered by
    discover_identity_fields_by_llm() (or the static fallback). Only called
    when compute_response_similarity() already confirmed the two bodies
    share the same JSON schema."""

    baseline_json = try_parse_json(baseline_body)
    current_json = try_parse_json(current_body)
    if not isinstance(baseline_json, dict) and not isinstance(baseline_json, list):
        return "llm_error", None, None
    if not isinstance(current_json, dict) and not isinstance(current_json, list):
        return "llm_error", None, None

    baseline_flat = flatten_json(baseline_json)
    current_flat = flatten_json(current_json)

    changed_identity_fields = []
    for path, baseline_value in baseline_flat.items():
        if path not in current_flat:
            continue
        if current_flat[path] == baseline_value:
            continue
        if is_identity_field(path, identity_fields):
            changed_identity_fields.append(path)

    # similarity_score reused here as a diagnostic: number of identity-bearing
    # fields found to differ (0 = none changed -> UNAFFECTED/same record).
    diagnostic_count = len(changed_identity_fields)
    result = "vulnerable_by_llm" if diagnostic_count > 0 else "unaffected_by_llm"
    return result, diagnostic_count, None


# ==============================
# REQUEST PARSING (copied verbatim from simple/parameter_mutation_fuzzing_attack.py)
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
    up at baseline-replay time. Copied verbatim from
    simple/parameter_mutation_fuzzing_attack.py -- see that module's
    docstring for why this matters (confirmed in practice: the same record's
    request Authorization header and session_detected entry decoded to
    different JWT iat/exp timestamps for the same user, meaning the raw
    captured request can carry an already-expired token)."""

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


def compute_response_similarity(baseline_body: str, replay_body: str):
    """Schema-only structural comparison, copied verbatim from
    simple/parameter_mutation_fuzzing_attack.py -- detect content type first,
    then compare structure (not values) via Jaccard similarity over
    (path, type) pairs. A volatile field (token/timestamp/random hash) still
    matches structurally even though its VALUE differs every request, since
    only its (path, type) pair -- not its value -- is compared. Used as a
    cheap, deterministic PRE-CHECK before running the Stage 2 field-diff
    (see evaluate()): if the structure doesn't match at all, the response is
    a rejection/error of a different shape and Stage 2 never needs to run."""

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


# ==============================
# PARAMETER DISCOVERY (copied verbatim from simple/parameter_mutation_fuzzing_attack.py)
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
    descended into -- the ground-truth dataset this module targets only
    seeds identifiers as top-level fields."""

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
# FUZZ VALUE GENERATION (copied verbatim)
# ==============================

def generate_fuzz_values(base_value: int, fuzz_range: int, sweep_direction: str = "both") -> List[int]:
    """Positive-only fuzz values around base_value, e.g. base=5, range=1,
    direction="both" -> [4,6] (0 and negatives are floored out, base_value
    itself is excluded since mutating a parameter to its own value isn't a
    mutation).

    sweep_direction controls which side(s) of base_value are tried:
      - "both" (default): base-fuzz_range .. base+fuzz_range, e.g. [4,6] for
        base=5, range=1. This is the option kept available for other runs.
      - "up": base+1 .. base+fuzz_range only, e.g. [6] for base=5, range=1.
      - "down": base-fuzz_range .. base-1 only (still floored at 1), e.g.
        [4] for base=5, range=1.
    The +id/-id sweep feature itself is unchanged -- sweep_direction only
    selects which side(s) filter_records() actually requests for a given
    run (see EXTRA_INPUTS in config.py)."""

    low = max(1, base_value - fuzz_range)
    high = base_value + fuzz_range

    if sweep_direction == "up":
        low = base_value + 1
    elif sweep_direction == "down":
        high = base_value - 1

    return [v for v in range(low, high + 1) if v != base_value]


# ==============================
# REFERENCE MUTATION (BACFuzz-inspired -- see paper/dharmaadi -bacfuzz.pdf
# Section 4.2.3 "Mutation"; copied verbatim from simple/parameter_mutation_fuzzing_attack.py)
# ==============================
#
# In addition to the +/-N sweep above, also try values that are KNOWN to be
# real, valid identifiers because they were observed as this SAME parameter
# key on a DIFFERENT user's baseline request. Built from
# extra_inputs["_all_baseline_records"] -- every record from the SAME
# baseline file the user selected in main().

_reference_value_cache: Dict[int, Dict[str, List[int]]] = {}


def _build_reference_value_index(all_baseline_records: List[Dict[str, Any]]) -> Dict[str, List[int]]:
    """key -> sorted list of distinct integer values seen for that parameter
    key (path[N] / query:name / body:name) across ALL "ambiguous" baseline
    records, regardless of which user or endpoint they came from (reference
    pool is scoped to classification=="ambiguous" since that's this module's
    universe -- a "simple" endpoint's identifier space isn't necessarily the
    same as an "ambiguous" one's). Cached by id(all_baseline_records) so it's
    built once per attack run, not once per record."""

    index: Dict[str, set] = {}
    for record in all_baseline_records:
        if record.get("classification") != "ambiguous":
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
    across the whole "ambiguous" baseline (any user, any endpoint), excluding
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
# REQUEST MUTATION (copied verbatim from simple/parameter_mutation_fuzzing_attack.py)
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

def filter_records(records: List[Dict[str, Any]], extra_inputs: Dict[str, str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Mirror of simple/parameter_mutation_fuzzing_attack.py's filter_records(),
    with the classification check FLIPPED:

      1. Restrict to classification=="ambiguous" records that have at least
         one fuzzable numeric parameter (path/query/body). classification=="simple"
         records are excluded outright (that's simple/parameter_mutation_fuzzing's
         job, not this module's).
      2. EXPAND each surviving record into one synthetic "attempt record" per
         (parameter, fuzz value) combination -- same fan-out reasoning as the
         "simple" counterpart (see that module's docstring)."""

    try:
        fuzz_range = int(extra_inputs.get("fuzz_range", "").strip())
    except (ValueError, AttributeError):
        fuzz_range = DEFAULT_FUZZ_RANGE
    if fuzz_range < 1:
        fuzz_range = DEFAULT_FUZZ_RANGE

    sweep_direction = (extra_inputs.get("sweep_direction") or "").strip().lower()
    if sweep_direction not in ("both", "up", "down"):
        sweep_direction = DEFAULT_SWEEP_DIRECTION

    all_baseline_records = extra_inputs.get("_all_baseline_records", [])

    kept: List[Dict[str, Any]] = []
    excluded: List[Dict[str, Any]] = []

    for record in records:
        if record.get("classification") != "ambiguous":
            excluded.append({"record": record, "reason": "not classification=ambiguous -- excluded from ambiguous-model parameter mutation fuzzing"})
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

            sweep_values = generate_fuzz_values(base_value, fuzz_range, sweep_direction)
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
    """One row per ENDPOINT (not per attempt) after aggregate_outcomes()
    collapses every (parameter, fuzz value) attempt down -- same shape as
    simple/parameter_mutation_fuzzing_attack.py:
      - parameter_affected: "key=value,key2=value2" -- one sample value per
        parameter the two-stage oracle judged VULNERABLE for this endpoint
        (empty if none).
      - value_test: "key=min-max,key2=min-max" -- the full range of values
        actually attempted for each fuzzable parameter on this endpoint,
        regardless of outcome (documents test coverage)."""

    return ["parameter_affected", "value_test"]


def evaluate(plan: Dict[str, Any], attack_result: "engine.AttackResult", response_index: Dict[str, str],
             extra_inputs: Dict[str, str]) -> Dict[str, Any]:
    """Turn a successful AttackResult into VULNERABLE/UNAFFECTED/UNCERTAIN for
    one (parameter, fuzz value) attempt, using a TWO-STAGE oracle (see the
    "TWO-STAGE ORACLE" comment block above discover_identity_fields_by_llm()
    for the full rationale):

    Stage 1 -- structural pre-check (compute_response_similarity(), the same
    schema-only Jaccard comparison the "simple" module uses):
    - structural similarity < 100 -> UNAFFECTED immediately, no Stage 2 call.
      A volatile field's VALUE changing doesn't break this check (only its
      (path, type) is compared), so a structural mismatch reliably means a
      differently-shaped response (rejection/error), not just "one field is
      random."

    Stage 2 -- only when structure DOES match (both are the same JSON shape,
    plausibly the "real" resource being returned either way):
    - discover_identity_fields_by_llm() -- Qwen2.5:3B is asked ONCE per
      distinct baseline body to name which of ITS OWN top-level field names
      are identity-bearing (name/email/employee id/etc.), not to compare two
      responses or judge identity directly (the task five earlier prompt
      designs failed at -- see module docstring).
    - classify_data_identity_by_field_diff() -- deterministic Python: flags
      the attempt VULNERABLE if at least one of those discovered
      identity-bearing fields' VALUE changed between baseline and current
      response (another user's identifying data leaked through), UNAFFECTED
      if only non-identity/volatile fields differ (or nothing differs).

    UNCERTAIN: no baseline response body could be found in response_index
    for this record's knumal_resp (candidate.json doesn't have it) --
    nothing to compare against, neither stage runs."""

    record = plan["record"]
    endpoint = record.get("endpoint", "UNKNOWN")

    replay_hash = hash_response_body(attack_result.response_body)
    baseline_hash = record.get("knumal_resp")
    baseline_body = response_index.get(baseline_hash, "")

    fuzz_source = record.get("_fuzz_source", "")
    fuzz_key = record.get("_fuzz_key", "")
    fuzz_original = record.get("_fuzz_original_value", "")
    fuzz_mutated = record.get("_fuzz_mutated_value", "")
    fuzz_mutation_kind = record.get("_fuzz_mutation_kind", "")

    if not baseline_body:
        result = "UNCERTAIN"
        similarity_score = "-"
        description = (f"[UNCERTAIN] {endpoint} - {fuzz_key} ({fuzz_source}, {fuzz_mutation_kind}) "
                        f"{fuzz_original} -> {fuzz_mutated} - no baseline response body found for "
                        f"comparison (parameter mutation fuzzing)")
    else:
        structural_similarity = compute_response_similarity(baseline_body, attack_result.response_body)

        if structural_similarity == "-" or structural_similarity < 100.0:
            # Stage 1 rejected it: different shape -> clean rejection, no Stage 2 call.
            result = "UNAFFECTED"
            similarity_score = structural_similarity
            description = (f"[UNAFFECTED] {endpoint} - {fuzz_key} ({fuzz_source}, {fuzz_mutation_kind}) "
                            f"{fuzz_original} -> {fuzz_mutated} rejected (structural mismatch, "
                            f"similarity={structural_similarity}, no Stage 2 check needed) "
                            f"(parameter mutation fuzzing)")
        else:
            # Stage 2: structure matches. Get (or discover, once per
            # baseline) this endpoint's identity-bearing field names, then
            # run the deterministic field-diff heuristic against them.
            identity_fields = discover_identity_fields_by_llm(baseline_hash, baseline_body)
            diff_result, score, _confidence = classify_data_identity_by_field_diff(
                baseline_body, attack_result.response_body, identity_fields
            )
            similarity_score = "-" if score is None else score

            if diff_result == "vulnerable_by_llm":
                result = "VULNERABLE"
                description = (f"[VULNERABLE] {endpoint} - {fuzz_key} ({fuzz_source}, {fuzz_mutation_kind}) "
                                f"{fuzz_original} -> {fuzz_mutated} returned another user's object "
                                f"(structural match, identity field(s) changed, "
                                f"changed_identity_fields={similarity_score}) (parameter mutation fuzzing)")
            elif diff_result == "unaffected_by_llm":
                result = "UNAFFECTED"
                description = (f"[UNAFFECTED] {endpoint} - {fuzz_key} ({fuzz_source}, {fuzz_mutation_kind}) "
                                f"{fuzz_original} -> {fuzz_mutated} returned own data unchanged "
                                f"(structural match, no identity field changed, "
                                f"changed_identity_fields={similarity_score}) (parameter mutation fuzzing)")
            else:  # error (unparseable JSON)
                result = "UNCERTAIN"
                description = (f"[UNCERTAIN] {endpoint} - {fuzz_key} ({fuzz_source}, {fuzz_mutation_kind}) "
                                f"{fuzz_original} -> {fuzz_mutated} - response body not parseable as JSON "
                                f"for field-diff comparison (parameter mutation fuzzing)")

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
        "response_similarity": similarity_score,
        "result": result,
        "description": description,
        "error": None,
    }


# ==============================
# POST-RUN AGGREGATION (optional engine hook, see knumal-att4ck.py's main())
# ==============================
#
# Same collapsing logic as simple/parameter_mutation_fuzzing_attack.py's
# aggregate_outcomes(): EXACTLY ONE row per original endpoint.
#   - parameter_affected: "key=value,key2=value2" -- one sample value per
#     parameter the two-stage oracle judged VULNERABLE (picked at random
#     among that parameter's vulnerable attempts if more than one qualified).
#   - value_test: "key=min-max,key2=min-max" -- for EVERY fuzzable parameter
#     on this endpoint, the full min-max range of values attempted.
#   - current_req (curl_command): one curl command per parameter listed in
#     parameter_affected, joined by newlines -- falls back to the first
#     attempt's curl command if nothing was vulnerable.
#   - result: VULNERABLE if parameter_affected is non-empty; else UNCERTAIN
#     if EVERY attempt for this endpoint came back UNCERTAIN (no baseline
#     body / unparseable JSON -- nothing could be judged at all); else
#     UNAFFECTED.

def _format_value_test(min_v: int, max_v: int) -> str:
    """"min-max", or just "min" when only one value was tried for that key."""

    return str(min_v) if min_v == max_v else f"{min_v}-{max_v}"


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
    all_uncertain = all(a["result"] == "UNCERTAIN" for a in attempts)

    if is_vulnerable:
        result = "VULNERABLE"
    elif all_uncertain:
        result = "UNCERTAIN"
    else:
        result = "UNAFFECTED"

    parameter_affected = ",".join(parameter_affected_parts)
    value_test = ",".join(value_test_parts)
    curl_command = "\n".join(curl_commands) if curl_commands else attempts[0]["curl_command"]

    if is_vulnerable:
        description = (f"[VULNERABLE] {endpoint} - parameter(s) {parameter_affected} returned "
                        f"another user's object, identity-field-diff judged (parameter mutation fuzzing)")
    elif all_uncertain:
        description = (f"[UNCERTAIN] {endpoint} - {len(attempts)} parameter mutation attempt(s) "
                        f"tried ({value_test}), no baseline response body available for "
                        f"comparison (parameter mutation fuzzing)")
    else:
        description = (f"[UNAFFECTED] {endpoint} - {len(attempts)} parameter mutation attempt(s) "
                        f"tried ({value_test}), none judged vulnerable by identity-field-diff "
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

    return aggregated
