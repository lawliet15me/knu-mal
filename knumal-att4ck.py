#!/usr/bin/env python3
"""knumal-att4ck engine: the operational runtime shared by every attack model
(simple/ambiguous x anonymous/session_swapping/parameter_mutation_fuzzing).

This file owns everything that is a RUNTIME OPERATION, not an analysis
decision: loading baseline.json, picking domains, sending HTTP requests,
adaptive rate-limit handling (retry + shrinking thread pool), progress
reporting, and writing the result TSV.

Attack MODULES (under knumal_att4ck_modul/<model>/<attack>/) only implement
the ANALYSIS side, via two functions:

    build_attack_plan(record) -> dict
        Prepare method/url/headers/body/curl_command for one baseline record
        (e.g. anonymous strips the session header(s) from the request).

    evaluate(plan, attack_result, response_index) -> dict
        Given the live AttackResult, decide result (0/1), response_similarity,
        and a human-readable description of the outcome.

The engine calls these two functions and handles everything else."""
import csv
import glob
import importlib.util
import json
import os
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from bs4 import BeautifulSoup, Comment

# ==============================
# CONTENT-TYPE DETECTION (used before response_similarity comparisons)
# ==============================
#
# Same two-layer approach as knumal-1-read-xml.py: trust a Content-Type
# header if one is available (not the case here -- replay only gives us a
# response body, no header object), otherwise sniff the body itself. Returns
# one of "json" / "xml" / "html" / "other".


def detect_content_type_from_body(body: str) -> str:
    """Sniff a response body's content type. Attack modules call this before
    deciding how (or whether) to compute response_similarity: json/xml use
    compare_structure, html/other typically can't be schema-compared
    meaningfully (caller should fall back to "-")."""

    stripped = (body or "").strip()
    if not stripped:
        return "other"

    try:
        json.loads(stripped)
        return "json"
    except Exception:
        pass

    lowered = stripped.lower()
    if lowered.startswith("<?xml"):
        return "xml"

    if any(tag in lowered for tag in ("<html", "<!doctype html", "<div", "<body")):
        return "html"

    # A body starting with "<tag ...>" that isn't HTML-ish is likely bare XML
    # without an <?xml ...?> prolog (common in APIs that skip it).
    if stripped.startswith("<"):
        try:
            ET.fromstring(stripped)
            return "xml"
        except ET.ParseError:
            pass

    return "other"


# ==============================
# JSON STRUCTURE COMPARISON (used by attack modules for response_similarity)
# ==============================


def extract_schema(obj: Any, path: str = "") -> Set[Tuple[str, str]]:
    """Recursively walk a JSON value by DATA TYPE (not specific key names) and
    return a set of (path, type) pairs describing its shape. Arrays are
    represented by their first element only (as a schema sample)."""

    if isinstance(obj, dict):
        fields = {(path, "object")} if path else set()
        for key, value in obj.items():
            child_path = f"{path}.{key}" if path else key
            fields |= extract_schema(value, child_path)
        return fields

    if isinstance(obj, list):
        fields = {(path, "array")}
        if obj:
            fields |= extract_schema(obj[0], f"{path}[]")
        return fields

    if isinstance(obj, bool):
        return {(path, "bool")}

    if isinstance(obj, (int, float)):
        return {(path, "number")}

    if isinstance(obj, str):
        return {(path, "string")}

    if obj is None:
        return {(path, "null")}

    return {(path, type(obj).__name__)}


def jaccard_similarity(schema_a: Set[Tuple[str, str]], schema_b: Set[Tuple[str, str]]) -> Tuple[float, List[str], List[str]]:

    shared = schema_a & schema_b
    total_unique = schema_a | schema_b

    similarity = (len(shared) / len(total_unique) * 100) if total_unique else 100.0

    only_in_a = sorted(f"{path} ({type_})" for path, type_ in (schema_a - schema_b))
    only_in_b = sorted(f"{path} ({type_})" for path, type_ in (schema_b - schema_a))

    return similarity, only_in_a, only_in_b


def compare_structure(json_a: Any, json_b: Any) -> Tuple[float, List[str], List[str]]:
    """Compare two JSON structures via Jaccard similarity over their (path, type)
    schemas. Returns (similarity_percent, only_in_a, only_in_b)."""

    return jaccard_similarity(extract_schema(json_a), extract_schema(json_b))


# ==============================
# XML STRUCTURE COMPARISON (used by attack modules for response_similarity)
# ==============================


def sniff_xml_text_type(text: str) -> str:
    """Classify an XML element's text content as a primitive type (the XML
    analogue of extract_schema()'s number/bool/string split for JSON values).
    Tries int, then float, then bool ("true"/"false", case-insensitive),
    falling back to plain string."""

    stripped = text.strip()

    try:
        int(stripped)
        return "number"
    except ValueError:
        pass

    try:
        float(stripped)
        return "number"
    except ValueError:
        pass

    if stripped.lower() in ("true", "false"):
        return "bool"

    return "string"


def qualify_tag(tag: str, nsmap: Dict[str, str]) -> str:
    """Resolve a Clark-notation tag ("{uri}Local") back to its document
    prefix ("prefix:Local") using the xmlns declarations captured while
    parsing. Falls back to the bare local name (dropping the URI) if the
    namespace has no known prefix, and returns unqualified tags unchanged."""

    if not tag.startswith("{"):
        return tag

    uri, _, local = tag[1:].partition("}")
    prefix = nsmap.get(uri)
    return f"{prefix}:{local}" if prefix else local


def extract_schema_xml(element: Optional[ET.Element], path: str = "", nsmap: Optional[Dict[str, str]] = None) -> Set[Tuple[str, str]]:
    """Recursively walk an XML element by TAG STRUCTURE and return a set of
    (path, type) pairs describing its shape -- the XML analogue of
    extract_schema() for JSON. Each distinct child tag name becomes part of
    the path (attributes are recorded as "path/@attrname"); repeated siblings
    with the same tag collapse into one schema entry, same as
    extract_schema()'s "take the first array element" rule. Text content is
    typed as "number"/"bool"/"string" (sniffed, not the value itself) so a
    field changing from a number to a string between two responses is
    detected as a structural difference, same as it would be for JSON."""

    if element is None:
        return set()

    nsmap = nsmap or {}
    tag = qualify_tag(element.tag, nsmap)
    tag_path = f"{path}/{tag}" if path else tag
    fields = {(tag_path, "element")}

    for attr_name in element.attrib:
        fields.add((f"{tag_path}/@{qualify_tag(attr_name, nsmap)}", "attribute"))

    if element.text and element.text.strip():
        fields.add((f"{tag_path}/#text", sniff_xml_text_type(element.text)))

    seen_tags = set()
    for child in element:
        if child.tag in seen_tags:
            continue
        seen_tags.add(child.tag)
        fields |= extract_schema_xml(child, tag_path, nsmap)

    return fields


def try_parse_xml(text: str) -> Tuple[Optional[ET.Element], Dict[str, str]]:
    """Parse a string as XML, returning (None, {}) (not raising) on failure.
    Also collects the document's xmlns:prefix=uri declarations (ElementTree's
    normal parser discards these, storing only the expanded "{uri}Tag" form)
    so extract_schema_xml() can print readable "prefix:Tag" paths instead."""

    import io

    stripped = (text or "").strip()

    nsmap: Dict[str, str] = {}
    try:
        for event, elem in ET.iterparse(io.StringIO(stripped), events=("start-ns", "end")):
            if event == "start-ns":
                prefix, uri = elem
                if prefix:
                    nsmap[uri] = prefix
        root = ET.fromstring(stripped)
        return root, nsmap
    except Exception:
        return None, {}


def compare_structure_xml(xml_a: str, xml_b: str) -> Tuple[float, List[str], List[str]]:
    """Compare two XML documents (as raw strings) via Jaccard similarity over
    their tag-structure schemas. Returns (similarity_percent, only_in_a,
    only_in_b). If either fails to parse, similarity is 0.0 with both sides
    reported as entirely mismatched."""

    root_a, nsmap_a = try_parse_xml(xml_a)
    root_b, nsmap_b = try_parse_xml(xml_b)

    if root_a is None or root_b is None:
        return 0.0, [], []

    return jaccard_similarity(
        extract_schema_xml(root_a, nsmap=nsmap_a),
        extract_schema_xml(root_b, nsmap=nsmap_b),
    )


# ==============================
# HTML STRUCTURE COMPARISON (used by attack modules for response_similarity)
# ==============================
#
# Unlike JSON/XML, HTML text content is essentially always noise for VAPT
# purposes (product names, timestamps, per-request tokens) -- comparing it
# would make near-identical pages look "different" and mask real structural
# changes. So this is a DOM STRUCTURE FINGERPRINT: tag + class + id per node
# (e.g. "div.container#main > ul.items > li"), ignoring every other attribute
# (href/src/data-*/onclick, ...) and all text. <script>/<style>/comments are
# stripped before extraction since they're pure noise (inline JS/CSS/debug
# comments vary run to run without reflecting any real page structure
# change). Unlike extract_schema()/extract_schema_xml(), repeated siblings
# with the same tag+class are NOT collapsed -- each occurrence is counted
# (e.g. 5 vs 3 "li.item" under the same parent is itself a meaningful
# structural difference for a VAPT diff, not noise).

HTML_NOISE_TAGS = ("script", "style")


def _node_selector(tag) -> str:
    """Build a CSS-like "tag.class1.class2#id" label for one BeautifulSoup
    tag, ignoring every attribute except class/id."""

    classes = sorted(tag.get("class", []))
    selector = tag.name + "".join(f".{c}" for c in classes)

    node_id = tag.get("id")
    if node_id:
        selector += f"#{node_id}"

    return selector


def extract_schema_html(soup: "BeautifulSoup") -> Set[Tuple[str, str]]:
    """Walk a parsed HTML document and return a set of (path, "element")
    pairs fingerprinting its DOM structure. Each element's path is its
    ancestor chain of "tag.class#id" selectors joined by " > ". Sibling
    index is folded into the path (not collapsed) so repeated structures
    (e.g. a list of cards) contribute their actual count to the schema."""

    fields: Set[Tuple[str, str]] = set()

    def walk(node, ancestor_path: str, sibling_index: int):
        selector = _node_selector(node)
        node_path = f"{ancestor_path} > {selector}[{sibling_index}]" if ancestor_path else f"{selector}[{sibling_index}]"
        fields.add((node_path, "element"))

        child_counts: Dict[str, int] = {}
        for child in node.find_all(True, recursive=False):
            child_selector = _node_selector(child)
            index = child_counts.get(child_selector, 0)
            child_counts[child_selector] = index + 1
            walk(child, node_path, index)

    for top_level in soup.find_all(True, recursive=False):
        walk(top_level, "", 0)

    return fields


def _strip_html_noise(soup: "BeautifulSoup") -> None:
    """Remove <script>/<style> tags and HTML comments in place -- inline
    JS/CSS and debug comments vary between requests without reflecting any
    real page structure change, so they'd otherwise dilute the similarity
    score with pure noise."""

    for tag in soup.find_all(HTML_NOISE_TAGS):
        tag.decompose()

    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()


def try_parse_html(text: str) -> Optional["BeautifulSoup"]:
    """Parse a string as HTML, returning None (not raising) on failure.
    Strips <script>/<style>/comments before returning, so callers always get
    a noise-free tree."""

    stripped = (text or "").strip()
    if not stripped:
        return None

    try:
        soup = BeautifulSoup(stripped, "lxml")
    except Exception:
        return None

    _strip_html_noise(soup)
    return soup


def compare_structure_html(html_a: str, html_b: str) -> Tuple[float, List[str], List[str]]:
    """Compare two HTML documents (as raw strings) via Jaccard similarity
    over their DOM structure fingerprints (tag.class#id path, sibling counts
    included). Returns (similarity_percent, only_in_a, only_in_b). If either
    fails to parse (or is empty), similarity is 0.0."""

    soup_a = try_parse_html(html_a)
    soup_b = try_parse_html(html_b)

    if soup_a is None or soup_b is None:
        return 0.0, [], []

    schema_a = extract_schema_html(soup_a)
    schema_b = extract_schema_html(soup_b)

    shared = schema_a & schema_b
    total_unique = schema_a | schema_b
    similarity = (len(shared) / len(total_unique) * 100) if total_unique else 100.0

    only_in_a = sorted(f"{path} ({type_})" for path, type_ in (schema_a - schema_b))
    only_in_b = sorted(f"{path} ({type_})" for path, type_ in (schema_b - schema_a))

    return similarity, only_in_a, only_in_b


# ==============================
# CONFIG
# ==============================

BASELINE_GLOB = "*.json"
CANDIDATE_FILENAME_HINT = "candidate"
REQUEST_TIMEOUT = 15
MAX_NON_RATE_LIMIT_ATTEMPTS = 3  # cap for non-rate-limit errors, and for rate-limit once the pool is at MIN_THREADS
RETRY_DELAY_SECONDS = 3
DEFAULT_THREADS = 10
DEFAULT_DELAY_MS = 1000
MIN_THREADS = 1
POOL_SHRINK_FACTOR = 0.33  # keep 33% (i.e. -67%) whenever a rate-limit is detected
RATE_LIMIT_STATUS_CODES = {429, 502, 503, 504}

RED = "\033[91m"
RESET = "\033[0m"
DIM = "\033[2m"

MODELS = ["simple", "ambiguous"]
MODUL_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "knumal_att4ck_modul")


class AttackResult:

    def __init__(self, response_body: Optional[str] = None, status_code: Optional[int] = None,
                 error: Optional[str] = None, is_timeout: bool = False):
        self.response_body = response_body
        self.status_code = status_code
        self.error = error
        self.is_timeout = is_timeout


# ==============================
# PLUGIN DISCOVERY (config.py based)
# ==============================

def _load_config_module(config_path: str):
    """Import a config.py by path. Returns None if it can't be loaded."""

    try:
        spec = importlib.util.spec_from_file_location("attack_config", config_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


def discover_attacks(model: str) -> List[Dict[str, Any]]:
    """Scan knumal_att4ck_modul/<model>/*/config.py and return metadata for
    every attack folder found, enabled or not (menu rendering decides what
    to show)."""

    model_dir = os.path.join(MODUL_ROOT, model)
    if not os.path.isdir(model_dir):
        return []

    discovered = []
    for entry in sorted(os.listdir(model_dir)):
        folder = os.path.join(model_dir, entry)
        config_path = os.path.join(folder, "config.py")

        if not os.path.isdir(folder) or not os.path.isfile(config_path):
            continue

        config = _load_config_module(config_path)
        if config is None:
            continue

        discovered.append({
            "folder": folder,
            "menu_name": getattr(config, "MENU_NAME", entry),
            "enable": bool(getattr(config, "ENABLE", False)),
            "attack_script": getattr(config, "ATTACK_SCRIPT", None),
            "extra_inputs": getattr(config, "EXTRA_INPUTS", []),
            "result_labels": getattr(config, "RESULT_LABELS", {}),
        })

    return discovered


def choose_model_and_attack() -> Tuple[str, Dict[str, Any]]:
    """Interactively pick a model, then an ENABLED attack within it.
    Disabled attacks are shown greyed out but cannot be selected."""

    print("Attack model:")
    for idx, model in enumerate(MODELS, start=1):
        print(f"  {idx}. {model}")

    while True:
        choice = input(f"Select model [1-{len(MODELS)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(MODELS):
            model = MODELS[int(choice) - 1]
            break
        print("[!] Invalid selection, try again.")

    attacks = discover_attacks(model)
    enabled_attacks = [a for a in attacks if a["enable"]]

    print(f"\nAttack type ({model}):")
    for idx, attack in enumerate(attacks, start=1):
        label = f"  {idx}. {attack['menu_name']}"
        if not attack["enable"]:
            label = f"{DIM}{label} (disabled){RESET}"
        print(label)

    if not enabled_attacks:
        raise SystemExit(f"[!] No enabled attack found under knumal_att4ck_modul/{model}/.")

    while True:
        choice = input(f"Select attack [1-{len(attacks)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(attacks):
            selected = attacks[int(choice) - 1]
            if selected["enable"]:
                return model, selected
            print("[!] That attack is disabled, pick another.")
            continue
        print("[!] Invalid selection, try again.")


def load_attack_module(attack_info: Dict[str, Any]):
    """Import the ATTACK_SCRIPT named in config.py, from the same folder."""

    script_name = attack_info.get("attack_script")
    if not script_name:
        raise SystemExit(f"[!] config.py in {attack_info['folder']} does not define ATTACK_SCRIPT.")

    module_path = os.path.join(attack_info["folder"], script_name)
    if not os.path.isfile(module_path):
        raise SystemExit(f"[!] Attack script not found: {module_path}")

    spec = importlib.util.spec_from_file_location(script_name.replace(".py", ""), module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ask_extra_inputs(extra_inputs: List[Dict[str, str]], records: Optional[List[Dict[str, Any]]] = None) -> Dict[str, str]:
    """Prompt the user for every extra input declared in config.py's EXTRA_INPUTS.

    Most entries are plain free-text (no "type", or "type": "text"). An entry
    can instead declare "type": "user_select" to render a numbered menu of
    every distinct user_login found in `records` (record["_user_login"]) --
    used by attacks like session_swapping that need to pick a real,
    already-known username rather than have the user type one blind.
    `records` is only needed for "user_select" entries; plain-text entries
    ignore it."""

    answers = {}
    for spec in extra_inputs:
        name = spec["name"]
        prompt = spec.get("prompt", name)

        if spec.get("type") == "user_select":
            answers[name] = _ask_user_select(prompt, records or [])
        else:
            answers[name] = input(f"{prompt}: ").strip()

    return answers


def _ask_user_select(prompt: str, records: List[Dict[str, Any]]) -> str:
    """Render a numbered menu of distinct user_login values (with endpoint
    counts) found in `records`, and return the chosen one."""

    counts: Dict[str, int] = {}
    for record in records:
        user_login = record.get("_user_login", "unknown")
        counts[user_login] = counts.get(user_login, 0) + 1

    users = sorted(counts.keys(), key=lambda u: counts[u], reverse=True)

    if not users:
        print(f"[!] No users found in the selected baseline/domain(s) -- falling back to free text.")
        return input(f"{prompt}: ").strip()

    print(f"{prompt}:")
    for idx, user_login in enumerate(users, start=1):
        print(f"  {idx}. {user_login} ({counts[user_login]} endpoint)")

    while True:
        choice = input(f"Select [1-{len(users)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(users):
            return users[int(choice) - 1]
        print("[!] Invalid choice, try again.")


# ==============================
# LOAD BASELINE FILE
# ==============================

def find_baseline_files(folder: str = ".") -> List[str]:

    found = []

    for path in sorted(glob.glob(os.path.join(folder, BASELINE_GLOB))):
        if CANDIDATE_FILENAME_HINT in os.path.basename(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        if isinstance(data, dict) and "cluster" in data:
            found.append(path)

    found.sort(key=lambda p: os.path.getmtime(p), reverse=True)

    return found


def choose_baseline_file(files: List[str]) -> str:

    print("Available baseline files (newest first):")
    for idx, path in enumerate(files, start=1):
        print(f"  {idx}. {path}")

    while True:
        choice = input(f"Select a file [1-{len(files)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(files):
            return files[int(choice) - 1]
        print("[!] Invalid selection, try again.")


def choose_candidate_file(files: List[str]) -> Optional[str]:
    """Same idea as choose_baseline_file(), but for candidate.json files (used
    for response_similarity's baseline body lookup). Auto-picks the only file
    without prompting when there's just one -- prompts (newest first) when
    there's more than one, since silently picking files[0] ("newest") can
    pick a candidate.json for a completely different target than the
    baseline file the user just selected (bit us in practice with
    session_swapping -- see session_swapping_design.md)."""

    if not files:
        return None

    if len(files) == 1:
        return files[0]

    print("Multiple candidate.json files found (newest first) -- pick the one matching your baseline file's target:")
    for idx, path in enumerate(files, start=1):
        print(f"  {idx}. {path}")

    while True:
        choice = input(f"Select a file [1-{len(files)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(files):
            return files[int(choice) - 1]
        print("[!] Invalid selection, try again.")


def find_tsv_result_files(folder: str = ".") -> List[str]:
    """Find *.tsv files that look like an attack result (has a "result"
    column) -- used by standalone post-processing modules like
    ambiguous/anonymous that read a previously-produced TSV instead of
    replaying HTTP requests."""

    found = []
    for path in sorted(glob.glob(os.path.join(folder, "*.tsv"))):
        try:
            with open(path, "r", encoding="utf-8", newline="") as f:
                header = f.readline().rstrip("\r\n").split("\t")
        except Exception:
            continue

        if "result" in header:
            found.append(path)

    found.sort(key=lambda p: os.path.getmtime(p), reverse=True)

    return found


def choose_tsv_file(files: List[str]) -> str:

    print("Available result TSV files (newest first):")
    for idx, path in enumerate(files, start=1):
        print(f"  {idx}. {path}")

    while True:
        choice = input(f"Select a file [1-{len(files)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(files):
            return files[int(choice) - 1]
        print("[!] Invalid selection, try again.")


def load_baseline_records(path: str) -> List[Dict[str, Any]]:
    """Flatten cluster[].children[].children[] into a list of records,
    each tagged with its host and user_login."""

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    records = []
    for host_entry in data.get("cluster", []):
        host = host_entry.get("host")
        for user_entry in host_entry.get("children", []):
            user_login = user_entry.get("user")
            for record in user_entry.get("children", []):
                record = dict(record)
                record["_host"] = host
                record["_user_login"] = user_login
                records.append(record)

    return records


# ==============================
# DOMAIN SELECTION
# ==============================

def build_domain_stats(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:

    by_domain: Dict[str, Dict[str, int]] = {}

    for record in records:
        host = record.get("_host", "unknown")
        user_login = record.get("_user_login", "unknown")
        by_domain.setdefault(host, {})
        by_domain[host][user_login] = by_domain[host].get(user_login, 0) + 1

    return by_domain


def render_domain_menu(domains: List[str], by_domain: Dict[str, Dict[str, int]], selected: List[str]) -> None:

    print("Domain Summary")
    print("=" * 70)

    for idx, host in enumerate(domains, start=1):
        users = by_domain[host]
        total = sum(users.values())

        label = f"{idx}. {host} ({total} endpoint)"
        if host in selected:
            label = f"{RED}{label} [selected]{RESET}"
        print(label)

        print(f"   Total users       : {len(users)}")
        for user_login, count in sorted(users.items(), key=lambda kv: kv[1], reverse=True):
            print(f"     - {user_login} ({count} endpoint)")

    print("=" * 70)


def _domain_selection_prompt(domains: List[str], selected: List[str]) -> str:

    if selected:
        return "Add another domain? [number, blank to continue, or 'all']: "
    return f"Select domain(s) to attack [1-{len(domains)}, or 'all']: "


def choose_domains(domains: List[str], by_domain: Dict[str, Dict[str, int]]) -> List[str]:

    selected: List[str] = []

    while True:
        render_domain_menu(domains, by_domain, selected)

        choice = input(_domain_selection_prompt(domains, selected)).strip().lower()

        if choice == "":
            if selected:
                return selected
            print("[!] No domain selected yet.")
            continue

        if choice == "all":
            return domains

        if choice.isdigit() and 1 <= int(choice) <= len(domains):
            host = domains[int(choice) - 1]
            if host in selected:
                selected.remove(host)
            else:
                selected.append(host)
            continue

        print("[!] Invalid choice, try again.")


# ==============================
# CANDIDATE.JSON LOOKUP (for response_similarity baseline body)
# ==============================

def find_candidate_files(folder: str = ".") -> List[str]:

    found = []
    for path in sorted(glob.glob(os.path.join(folder, BASELINE_GLOB))):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        if isinstance(data, dict) and "candidate" in data:
            found.append(path)

    found.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return found


def extract_raw_response_body(raw_response: str) -> str:

    raw_response = (raw_response or "").replace("\r\n", "\n")
    _, sep, body = raw_response.partition("\n\n")
    return body if sep else ""


def build_response_index_by_knumal_resp(candidate_path: str) -> Dict[str, str]:
    """Map knumal_resp -> raw response body, scanning candidate.json traffic."""

    with open(candidate_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    index: Dict[str, str] = {}
    for cand in data.get("candidate", []):
        for record in cand.get("traffic", []):
            knumal_resp = record.get("knumal_resp")
            if knumal_resp and knumal_resp not in index:
                index[knumal_resp] = extract_raw_response_body(record.get("response", ""))

    return index


# ==============================
# HTTP EXECUTION (generic, model-agnostic)
# ==============================

def send_request(method: str, url: str, headers: Dict[str, str], body: str) -> AttackResult:

    ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE")
    verify = ca_bundle if ca_bundle else False

    if not verify:
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=body.encode() if body else None,
            timeout=REQUEST_TIMEOUT,
            verify=verify,
        )
    except requests.exceptions.Timeout as e:
        return AttackResult(error=f"{type(e).__name__}: {e}", is_timeout=True)
    except requests.RequestException as e:
        return AttackResult(error=f"{type(e).__name__}: {e}")

    if response.status_code in RATE_LIMIT_STATUS_CODES:
        return AttackResult(status_code=response.status_code, error=f"rate_limited_status_{response.status_code}", is_timeout=True)

    return AttackResult(response_body=response.content.decode(errors="ignore"), status_code=response.status_code)


# ==============================
# PRE-ATTACK FILTERING (optional, per-module)
# ==============================
#
# Some attacks need to drop records BEFORE any replay happens, based on a
# comparison across the whole records list (not just one record at a time,
# which is all build_attack_plan()/evaluate() ever see). E.g. session_swapping
# doesn't need to test an endpoint that source_user already has access to
# themselves (same knumal_req == same request fingerprint) -- swapping
# source_user's own session into their own already-accessible endpoint isn't
# a meaningful BAC test.
#
# A module opts in by defining a module-level filter_records(records,
# extra_inputs) -> (kept_records, excluded) where `excluded` is a list of
# {"record": ..., "reason": "..."} dicts. Modules that don't define it keep
# every record unchanged.

def apply_pre_attack_filter(records: List[Dict[str, Any]], attack_module,
                             extra_inputs: Dict[str, str]) -> List[Dict[str, Any]]:

    filter_records = getattr(attack_module, "filter_records", None)
    if filter_records is None:
        return records

    kept, excluded = filter_records(records, extra_inputs)

    print(f"[+] Pre-attack filter: total {len(excluded)} endpoint(s) excluded, {len(kept)} remaining")

    excluded_by_reason: Dict[str, List[Dict[str, Any]]] = {}
    for item in excluded:
        excluded_by_reason.setdefault(item["reason"], []).append(item["record"])

    for reason, group_records in excluded_by_reason.items():
        print(reason)
        for record in group_records:
            url = build_full_url_for_display(record)
            method = record.get("request", "").split(" ", 1)[0] or "UNKNOWN"
            print(f"- {url} ({method}, {record.get('knumal_req', '')})")
        print()

    return kept


def build_full_url_for_display(record: Dict[str, Any]) -> str:
    """Best-effort full URL for a baseline record, for terminal display only
    (pre-attack filter exclusions, etc). Uses the same protocol/host/port
    rules as the attack modules' build_url(), plus the endpoint's path."""

    protocol = record.get("protocol", "https")
    host = record.get("host") or record.get("_host", "")
    port = record.get("port")

    default_port = {"https": "443", "http": "80"}.get(protocol)
    netloc = host if not port or port == default_port else f"{host}:{port}"

    endpoint = record.get("endpoint", "")
    path = endpoint.split(" ", 1)[1] if " " in endpoint else ""

    return f"{protocol}://{netloc}{path}"


# ==============================
# PROGRESS / ADAPTIVE ROUND EXECUTION
# ==============================

def render_progress_bar(completed: int, total: int, pool_size: int, width: int = 30) -> None:

    fraction = completed / total if total else 1.0
    filled = int(width * fraction)
    bar = "#" * filled + "-" * (width - filled)

    end = "\n" if completed == total else ""
    print(f"\r    [{bar}] {completed}/{total} (pool size: {pool_size})", end=end, flush=True)


def _run_attack_round(pending: List[Dict[str, Any]], pool_size: int, delay_ms: int,
                       attack_module, response_index: Dict[str, str], extra_inputs: Dict[str, str],
                       progress: Dict[str, Any], lock: threading.Lock):
    """Runs one ThreadPoolExecutor pass over `pending`. Returns (outcomes, next_round, had_rate_limit).

    Rate-limit hits retry indefinitely WHILE the pool can still shrink. Once
    pool_size has bottomed out at MIN_THREADS, they're capped at
    MAX_NON_RATE_LIMIT_ATTEMPTS too (there's nothing left to shrink to, so an
    unlimited retry would hang forever against a target that's simply down)."""

    def try_once(item):
        plan = item["plan"]
        result = send_request(plan["method"], plan["url"], plan["headers"], plan["body"])
        if delay_ms > 0:
            time.sleep(delay_ms / 1000)
        return result

    outcomes = []
    next_round = []
    had_rate_limit = False
    pool_at_floor = pool_size <= MIN_THREADS

    with ThreadPoolExecutor(max_workers=pool_size) as executor:
        futures = {executor.submit(try_once, item): item for item in pending}

        for future in futures:
            item = futures[future]
            attack_result = future.result()

            with lock:
                progress["completed"] += 1
                render_progress_bar(progress["completed"], progress["total"], pool_size)

            if attack_result.error is None:
                outcomes.append(attack_module.evaluate(item["plan"], attack_result, response_index, extra_inputs))
                continue

            if attack_result.is_timeout:
                had_rate_limit = True

                if not pool_at_floor:
                    next_round.append(item)
                    with lock:
                        progress["completed"] -= 1
                    continue

                item["attempt"] += 1
                if item["attempt"] < MAX_NON_RATE_LIMIT_ATTEMPTS:
                    next_round.append(item)
                    with lock:
                        progress["completed"] -= 1
                else:
                    with lock:
                        progress["skipped"] += 1
                        progress["skipped_records"].append({
                            "record": item["plan"]["record"],
                            "error": attack_result.error,
                        })
                continue

            item["attempt"] += 1
            if item["attempt"] < MAX_NON_RATE_LIMIT_ATTEMPTS:
                next_round.append(item)
                with lock:
                    progress["completed"] -= 1
            else:
                with lock:
                    progress["skipped"] += 1
                    progress["skipped_records"].append({
                        "record": item["plan"]["record"],
                        "error": attack_result.error,
                    })

    return outcomes, next_round, had_rate_limit


def _shrink_pool_if_needed(pool_size: int, had_rate_limit: bool) -> int:

    if not had_rate_limit or pool_size <= MIN_THREADS:
        return pool_size

    new_pool_size = max(MIN_THREADS, int(pool_size * POOL_SHRINK_FACTOR))
    if new_pool_size != pool_size:
        print(f"\n    [!] Rate-limit detected, shrinking parallel pool: {pool_size} -> {new_pool_size}", flush=True)

    return new_pool_size


def run_attacks(records: List[Dict[str, Any]], attack_module, response_index: Dict[str, str],
                threads: int, delay_ms: int, retry_delay_seconds: int,
                extra_inputs: Dict[str, str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int]:
    """Returns (completed_outcomes, failed_outcomes, safe_pool_size) where safe_pool_size
    is the smallest pool size that completed a round with zero rate-limit hits."""

    lock = threading.Lock()
    progress = {"completed": 0, "skipped": 0, "total": len(records), "skipped_records": []}

    completed_outcomes: List[Dict[str, Any]] = []
    pending = [{"plan": attack_module.build_attack_plan(r, extra_inputs), "attempt": 0} for r in records]
    pool_size = threads
    safe_pool_size = threads

    while pending:
        malformed = [item for item in pending if not item["plan"].get("method") or not item["plan"].get("path")]
        pending = [item for item in pending if item not in malformed]

        for item in malformed:
            progress["skipped"] += 1
            progress["skipped_records"].append({"record": item["plan"]["record"], "error": "malformed_request"})
            progress["completed"] += 1

        if not pending:
            break

        round_outcomes, pending, had_rate_limit = _run_attack_round(
            pending, pool_size, delay_ms, attack_module, response_index, extra_inputs, progress, lock
        )
        completed_outcomes.extend(round_outcomes)
        safe_pool_size = pool_size

        if had_rate_limit and pending:
            time.sleep(retry_delay_seconds)
            pool_size = _shrink_pool_if_needed(pool_size, had_rate_limit)

    print()

    for outcome in completed_outcomes:
        print(f"    {outcome['description']}")

    failed_outcomes = [
        {"record": item["record"], "curl_command": "", "response_similarity": 0.0, "result": None, "error": item["error"]}
        for item in progress["skipped_records"]
    ]

    return completed_outcomes, failed_outcomes, safe_pool_size


# ==============================
# TERMINAL REPORTING
# ==============================

DEFAULT_RESULT_LABELS = {
    "VULNERABLE": "response matches the baseline",
    "UNAFFECTED": "blocked / different response",
    "UNCERTAIN": "hash differs, http_status matches baseline",
}


def print_summary(attack_name: str, completed_outcomes: List[Dict[str, Any]],
                   failed_outcomes: List[Dict[str, Any]], safe_pool_size: int, delay_ms: int,
                   result_labels: Optional[Dict[str, str]] = None,
                   baseline_file: Optional[str] = None, candidate_file: Optional[str] = None,
                   extra_inputs: Optional[Dict[str, str]] = None) -> None:
    """result_labels lets an attack module's config.py override the wording
    of each bucket (e.g. anonymous: "accessible without auth", session_swapping:
    "accessible using another user's session") via RESULT_LABELS. Any key not
    supplied falls back to DEFAULT_RESULT_LABELS.

    baseline_file/candidate_file are echoed in the summary purely so the TSV
    output is traceable back to its exact input files later -- candidate_file
    is None when no candidate.json was found/selected.

    extra_inputs is the same dict ask_extra_inputs() built from the attack
    module's EXTRA_INPUTS (e.g. session_swapping's source_user) -- every key
    is echoed here generically so any current or future attack module's
    EXTRA_INPUTS show up automatically, without this function needing to know
    their names. Keys starting with "_" are engine-internal context (e.g.
    "_all_baseline_records", not a real prompt answer) and are skipped."""

    labels = {**DEFAULT_RESULT_LABELS, **(result_labels or {})}

    vulnerable = sum(1 for o in completed_outcomes if o["result"] == "VULNERABLE")
    unaffected = sum(1 for o in completed_outcomes if o["result"] == "UNAFFECTED")
    uncertain = sum(1 for o in completed_outcomes if o["result"] == "UNCERTAIN")

    print()
    print(f"{attack_name.replace('_', ' ').title()} Attack Summary")
    print("=" * 70)
    if baseline_file:
        input_files = baseline_file if not candidate_file else f"{baseline_file} + {candidate_file}"
        print(f"Input file(s) : {input_files}")
    for key, value in (extra_inputs or {}).items():
        if key.startswith("_"):
            continue
        print(f"{key} : {value}")
    print(f"Vulnerable ({labels['VULNERABLE']}) : {vulnerable}")
    print(f"Unaffected ({labels['UNAFFECTED']}) : {unaffected}")
    print(f"Uncertain ({labels['UNCERTAIN']}) : {uncertain}")
    print(f"Errors (non-rate-limit, after {MAX_NON_RATE_LIMIT_ATTEMPTS} attempts) : {len(failed_outcomes)}")
    print(f"Safe parallel thread count is {safe_pool_size} threads with delay {delay_ms} ms per request")
    print("=" * 70)

    if failed_outcomes:
        print("\nRequests that failed after all retries:")
        for outcome in failed_outcomes:
            endpoint = outcome["record"].get("endpoint", "UNKNOWN")
            print(f"    - {endpoint} ({outcome['error']})")


# ==============================
# TSV OUTPUT
# ==============================
#
# Column set (in file order):
#   knumal_req, knumal_resp, current_resp_hash, endpoint_class, endpoint, content_type,
#   current_req, login_info, session, current_resp_code, current_resp_data,
#   [EXTRA COLUMNS], response_similarity, result
#
#   - SHARED columns (everything except EXTRA) are always written by the
#     engine, identically for every attack model. "current_resp_hash" is the
#     hash of the live response for THIS attempt -- every attack module MUST
#     put it in the outcome dict returned by evaluate() (it's not optional
#     like EXTRA columns, since every attack compares a live response against
#     something). "endpoint_class" is the baseline record's own
#     "classification" field (record["classification"], set upstream in
#     baseline.json -- only ever "simple" or "ambiguous"), carried through
#     unchanged so a TSV row can be traced back to which baseline bucket
#     produced it. "content_type" is the BASELINE response's content type
#     (json/xml/html/other), taken from record["content-type"] -- set by
#     knumal-1-read-xml.py and carried unchanged through every later stage of
#     the pipeline. "login_info" is the user_login from baseline.json's
#     cluster[].children[].user (record["_user_login"]), taken straight from
#     `record` like the other baseline-derived columns. "current_resp_code" is
#     the live HTTP status code for THIS attempt (AttackResult.status_code) --
#     also mandatory, same as "current_resp_hash". "current_resp_data" is the
#     live response body for THIS attempt -- mandatory in the outcome dict
#     (was previously an attack-specific EXTRA column named "current_resp";
#     promoted to shared since every attack replays and inspects a live
#     response). "result" is expected to be one of "VULNERABLE" /
#     "UNAFFECTED" / "UNCERTAIN" (a hash mismatch but with a high
#     response_similarity means the response likely still leaks data through
#     a field that changes every request, e.g. a random token). "UNAFFECTED"
#     (not "CLEAN") because a target unaffected by THIS attack may still be
#     affected by a different one. "result" is always the LAST column.
#   - EXTRA columns are attack-specific (e.g. session_swapping adds
#     "source_user") and are inserted between "current_resp_data" and
#     "response_similarity". A module opts in by defining a module-level
#     get_extra_columns() -> List[str] that names the extra keys it puts in
#     the outcome dict returned by evaluate(). Modules that don't define it
#     get the shared columns only, unchanged.

SHARED_TSV_COLUMNS_BEFORE_EXTRA = [
    "knumal_req", "knumal_resp", "current_resp_hash", "endpoint_class", "endpoint", "content_type", "current_req", "login_info", "session",
    "current_resp_code", "current_resp_data",
]
SHARED_TSV_COLUMNS_AFTER_EXTRA = [
    "response_similarity", "result",
]


def get_extra_tsv_columns(attack_module) -> List[str]:

    get_extra_columns = getattr(attack_module, "get_extra_columns", None)
    if get_extra_columns is None:
        return []

    return list(get_extra_columns())


def escape_newlines(value: Any) -> Any:
    """Replace real CR/LF with literal \\r\\n text so every TSV row stays on
    exactly one physical line (safe to open in a plain text editor, grep,
    wc -l, etc). Non-string values pass through unchanged."""

    if not isinstance(value, str):
        return value

    return value.replace("\r\n", "\\r\\n").replace("\n", "\\n").replace("\r", "\\r")


# Excel's per-cell limit is 32767 characters -- a response body beyond this
# would render broken/truncated unpredictably if the TSV is opened in Excel.
# Cut well under that ceiling and mark the cut clearly rather than risk a
# silent, ambiguous truncation.
MAX_RESP_DATA_CELL_LENGTH = 30000


def truncate_cell_value(value: Any, max_length: int = MAX_RESP_DATA_CELL_LENGTH) -> Any:
    """Hard-truncate a string value at max_length characters and append a
    clear marker noting the original length. Non-string values and strings
    already within the limit pass through unchanged."""

    if not isinstance(value, str) or len(value) <= max_length:
        return value

    original_length = len(value)
    return f"{value[:max_length]}...[TRUNCATED, original {original_length} chars]"


def write_results_tsv(completed_outcomes: List[Dict[str, Any]], path: str, attack_module) -> None:

    extra_columns = get_extra_tsv_columns(attack_module)

    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(SHARED_TSV_COLUMNS_BEFORE_EXTRA + extra_columns + SHARED_TSV_COLUMNS_AFTER_EXTRA)

        for outcome in completed_outcomes:
            record = outcome["record"]
            row = [
                record.get("knumal_req", ""),
                record.get("knumal_resp", ""),
                outcome["current_resp_hash"],
                record.get("classification", ""),
                record.get("endpoint", ""),
                record.get("content-type", ""),
                outcome["curl_command"],
                record.get("_user_login", ""),
                json.dumps(record.get("session_detected", []), ensure_ascii=False),
                outcome["current_resp_code"],
                truncate_cell_value(outcome["current_resp_data"]),
            ]
            row += [outcome.get(col, "") for col in extra_columns]
            row += [
                outcome["response_similarity"],
                outcome["result"],
            ]
            writer.writerow([escape_newlines(v) for v in row])


# ==============================
# MAIN
# ==============================

def main():

    model, attack_info = choose_model_and_attack()
    attack_name = attack_info["menu_name"]
    attack_module = load_attack_module(attack_info)
    print(f"[+] Loaded attack module: {model}/{attack_name}")
    print()

    if hasattr(attack_module, "run_standalone"):
        run_standalone_module(attack_module)
        return

    baseline_files = find_baseline_files(".")
    if not baseline_files:
        print("[!] No baseline file (root key 'cluster') found.")
        return

    selected_file = choose_baseline_file(baseline_files)
    print(f"[+] Selected: {selected_file}")

    all_records = load_baseline_records(selected_file)
    print(f"[+] Total endpoints in baseline: {len(all_records)}")
    print()

    by_domain = build_domain_stats(all_records)
    domains = sorted(by_domain.keys(), key=lambda h: sum(by_domain[h].values()), reverse=True)
    selected_domains = choose_domains(domains, by_domain)
    print(f"[+] Selected domain(s): {', '.join(selected_domains)}")
    print()

    records = [r for r in all_records if r.get("_host") in selected_domains]
    print(f"[+] Total endpoints to attack: {len(records)}")
    print()

    # extra_inputs["_all_baseline_records"] carries every record from the
    # SAME baseline file the user just picked (not filtered to the selected
    # domain(s)) -- modules that need a cross-host/cross-user lookup (e.g.
    # session_swapping's "what session does user X use on host Y") should use
    # this instead of re-loading a baseline file themselves, since
    # find_baseline_files() sorts newest-first and could silently pick a
    # DIFFERENT file than the one selected here if more than one exists.
    extra_inputs = ask_extra_inputs(attack_info["extra_inputs"], records)
    extra_inputs["_all_baseline_records"] = all_records
    print()

    candidate_files = find_candidate_files(".")
    selected_candidate_file = choose_candidate_file(candidate_files)
    response_index: Dict[str, str] = {}
    if selected_candidate_file:
        response_index = build_response_index_by_knumal_resp(selected_candidate_file)
        print(f"[+] Using {selected_candidate_file} for baseline response bodies (response_similarity).")
    else:
        print("[!] No candidate.json found - response_similarity will be '-' for all records.")

    records = apply_pre_attack_filter(records, attack_module, extra_inputs)
    print()

    threads_raw = input(f"Number of parallel threads [{DEFAULT_THREADS}]: ").strip()
    threads = int(threads_raw) if threads_raw.isdigit() and int(threads_raw) >= 1 else DEFAULT_THREADS

    delay_raw = input(f"Delay between requests per thread (ms) [{DEFAULT_DELAY_MS}]: ").strip()
    delay_ms = int(delay_raw) if delay_raw.isdigit() and int(delay_raw) >= 0 else DEFAULT_DELAY_MS

    retry_delay_raw = input(f"Delay before retrying a rate-limited round (seconds) [{RETRY_DELAY_SECONDS}]: ").strip()
    retry_delay_seconds = int(retry_delay_raw) if retry_delay_raw.isdigit() and int(retry_delay_raw) >= 0 else RETRY_DELAY_SECONDS

    print(f"\n[+] Running {attack_name} attack...")
    completed_outcomes, failed_outcomes, safe_pool_size = run_attacks(
        records, attack_module, response_index, threads, delay_ms, retry_delay_seconds, extra_inputs
    )

    # Optional hook: a module that fans a single baseline record out into many
    # attempt outcomes (e.g. parameter_mutation_fuzzing_attack.py trying
    # several parameters x several fuzz values per record) can define
    # aggregate_outcomes(completed_outcomes) -> completed_outcomes to collapse
    # those attempts back down before the summary/TSV are produced -- e.g.
    # keeping every VULNERABLE attempt's detail but reducing an endpoint's
    # non-vulnerable attempts to a single summary row. Modules that don't
    # define this (anonymous, session_swapping, ...) are unaffected: getattr
    # returns None and completed_outcomes passes through unchanged.
    aggregate_outcomes = getattr(attack_module, "aggregate_outcomes", None)
    if aggregate_outcomes is not None:
        completed_outcomes = aggregate_outcomes(completed_outcomes)

    print_summary(attack_name, completed_outcomes, failed_outcomes, safe_pool_size, delay_ms,
                  attack_info.get("result_labels"), selected_file, selected_candidate_file, extra_inputs)

    baseline_basename = os.path.splitext(os.path.basename(selected_file))[0]
    baseline_prefix = baseline_basename[:-len("_baseline")] if baseline_basename.endswith("_baseline") else baseline_basename

    output_path = f"{baseline_prefix}_{attack_name}_attack_result.tsv"
    write_results_tsv(completed_outcomes, output_path, attack_module)
    print(f"\n[+] Results saved to {output_path}")

    if model == "simple":
        offer_ambiguous_triage(attack_name, selected_file, output_path)


# ==============================
# CHAINED FOLLOW-UP: ambiguous/<attack> LLM triage
# ==============================
#
# ambiguous/<folder> modules are not normal replay-based attack modules (see
# anonym_and_session_swap_llm.py's docstring for the pattern) -- each one
# post-processes the TSV a simple/<attack_name> run just wrote, so it's
# offered as an automatic follow-up right here instead of only being
# reachable from the model/attack menu.
#
# A module's config.py declares which simple/<attack_name> runs should
# trigger it via TRIGGERS = ["name1", "name2", ...] -- this does NOT assume
# the ambiguous/<folder> name matches attack_name (one ambiguous module can
# serve several simple attacks, e.g. anonym_and_session_swap serves both
# "anonymous" and "session_swapping"). Every ambiguous/* folder is scanned
# and the first one whose TRIGGERS contains attack_name is used.

def _find_triage_module_for(attack_name: str) -> Optional[Dict[str, Any]]:

    ambiguous_dir = os.path.join(MODUL_ROOT, "ambiguous")
    if not os.path.isdir(ambiguous_dir):
        return None

    for entry in sorted(os.listdir(ambiguous_dir)):
        attack_folder = os.path.join(ambiguous_dir, entry)
        config_path = os.path.join(attack_folder, "config.py")
        if not os.path.isfile(config_path):
            continue

        config = _load_config_module(config_path)
        if config is None or not getattr(config, "ATTACK_SCRIPT", None):
            continue

        if attack_name not in getattr(config, "TRIGGERS", []):
            continue

        module_path = os.path.join(attack_folder, config.ATTACK_SCRIPT)
        if not os.path.isfile(module_path):
            continue

        return {"folder_name": entry, "module_path": module_path, "attack_script": config.ATTACK_SCRIPT}

    return None


def offer_ambiguous_triage(attack_name: str, baseline_path: str, tsv_path: str) -> None:

    triage_info = _find_triage_module_for(attack_name)
    if triage_info is None:
        return

    with open(tsv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter="\t")
        uncertain_count = sum(1 for row in reader if row.get("result") == "UNCERTAIN")

    if uncertain_count == 0:
        return

    folder_name = triage_info["folder_name"]
    module_path = triage_info["module_path"]

    print(f"\n[+] {uncertain_count} UNCERTAIN row(s) found in {tsv_path}.")
    choice = input(f"Run ambiguous/{folder_name} LLM triage on them now? [Y/n]: ").strip().lower()
    if choice not in ("", "y", "yes"):
        return

    spec = importlib.util.spec_from_file_location(triage_info["attack_script"].replace(".py", ""), module_path)
    triage_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(triage_module)

    if not hasattr(triage_module, "run_standalone"):
        print(f"[!] {module_path} does not define run_standalone() -- skipping triage.")
        return

    print(f"\n[+] Running ambiguous/{folder_name} LLM triage ({triage_module.MODEL})...")
    print(f"[+] Press Ctrl+C at any time to cancel -- the {attack_name} attack result above is already saved either way.")
    try:
        triage_module.run_standalone(baseline_path, tsv_path)
    except KeyboardInterrupt:
        print("\n[!] Triage cancelled by user.")


# ==============================
# STANDALONE MODULES (post-processing, no HTTP replay)
# ==============================
#
# A module opts into this simpler flow by defining run_standalone(baseline_path,
# tsv_path) instead of build_attack_plan/evaluate -- main() detects this via
# hasattr() and skips the whole replay pipeline (domain selection, threads,
# delay, candidate.json, etc), since none of that applies to a module that
# only reads files that already exist on disk.

def run_standalone_module(attack_module) -> None:

    baseline_files = find_baseline_files(".")
    if not baseline_files:
        print("[!] No baseline file (root key 'cluster') found.")
        return

    selected_baseline = choose_baseline_file(baseline_files)
    print(f"[+] Selected baseline: {selected_baseline}")
    print()

    tsv_files = find_tsv_result_files(".")
    if not tsv_files:
        print("[!] No result TSV file (with a 'result' column) found.")
        return

    selected_tsv = choose_tsv_file(tsv_files)
    print(f"[+] Selected TSV: {selected_tsv}")
    print()

    print("[+] Press Ctrl+C at any time to cancel -- rows already processed are still written out as a partial result.")
    try:
        attack_module.run_standalone(selected_baseline, selected_tsv)
    except KeyboardInterrupt:
        print("\n[!] Cancelled by user.")


if __name__ == "__main__":
    main()
