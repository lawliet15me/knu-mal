#!/usr/bin/env python3
import base64
import csv
import glob
import hashlib
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests


# ==============================
# CONFIG
# ==============================

CANDIDATE_GLOB = "*.json"
REQUEST_TIMEOUT = 15
MAX_ATTEMPTS = 3  # cap for non-rate-limit errors, and for rate-limit once the pool is at MIN_THREADS
MIN_THREADS = 1
POOL_SHRINK_FACTOR = 0.33  # keep 33% (i.e. -67%) whenever a rate-limit/timeout is detected
RATE_LIMIT_STATUS_CODES = {429, 502, 503, 504}
UNKNOWN_ENDPOINT = "UNKNOWN UNKNOWN"


class ReplayResult:

    def __init__(self, fingerprint: Optional[str], skip_reason: Optional[str], is_timeout: bool = False,
                 session_headers: Optional[Dict[str, str]] = None):
        self.fingerprint = fingerprint
        self.skip_reason = skip_reason
        self.is_timeout = is_timeout
        self.session_headers = session_headers or {}


# ==============================
# LOAD CANDIDATE FILES
# ==============================

def find_candidate_files(folder: str = ".") -> List[str]:

    found = []

    for path in sorted(glob.glob(os.path.join(folder, CANDIDATE_GLOB))):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        if isinstance(data, dict) and "candidate" in data:
            found.append(path)

    found.sort(key=lambda p: os.path.getmtime(p), reverse=True)

    return found


def parse_traffic_time(time_str: str) -> datetime:

    try:
        parts = time_str.split()
        cleaned = " ".join(parts[:4] + [parts[5]])
        return datetime.strptime(cleaned, "%a %b %d %H:%M:%S %Y")
    except Exception:
        return datetime.min


def choose_candidate_file(files: List[str]) -> str:

    print("Available candidate files (newest first):")
    for idx, path in enumerate(files, start=1):
        mtime = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
        print(f"  {idx}. {path}  (modified: {mtime})")

    while True:
        choice = input(f"Select a file [1-{len(files)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(files):
            return files[int(choice) - 1]
        print("[!] Invalid selection, try again.")


def load_candidates_from_file(path: str) -> List[Dict[str, Any]]:

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return data.get("candidate", [])


# ==============================
# FILTER:
# per user -> domains -> domain & session -> traffic -> dedup by
# knumal_req (keep latest) -> filter requests that have a session header
# ==============================

def record_domain(record: Dict[str, Any]) -> str:
    """Build the "host[:port]" string for a traffic record, matching the
    format knumal-0-browser.py stores in session_analysis[].domain
    (urlparse().netloc -- no port suffix for the protocol's default port)."""

    host = record.get("host")
    port = record.get("port")
    protocol = record.get("protocol", "https")

    default_port = {"https": "443", "http": "80"}.get(protocol)

    if not port or port == default_port:
        return host

    return f"{host}:{port}"


def get_request_header_names(raw_request: str) -> set:

    raw_request = (raw_request or "").replace("\r\n", "\n")
    names = set()

    for line in raw_request.split("\n")[1:]:
        stripped = line.strip()
        if stripped == "":
            break
        if ":" in stripped:
            key, _ = stripped.split(":", 1)
            names.add(key.strip().lower())

    return names


def dedup_latest_by_knumal_req(traffic: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """For traffic sharing the same knumal_req, keep only the most recent record."""

    latest_by_hash: Dict[str, Dict[str, Any]] = {}

    for record in traffic:
        req_hash = record.get("knumal_req")
        if not req_hash:
            continue

        current = latest_by_hash.get(req_hash)
        if current is None or parse_traffic_time(record.get("time", "")) > parse_traffic_time(current.get("time", "")):
            latest_by_hash[req_hash] = record

    return list(latest_by_hash.values())


def filter_candidate_traffic(cand: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return traffic (with _user attached) for one candidate (user) that
    passes the valid-domain filter + latest knumal_req dedup + session header check."""

    user = cand.get("user", {})
    traffic = cand.get("traffic", [])

    result: List[Dict[str, Any]] = []

    for domain_entry in user.get("domains", []):
        domain = domain_entry.get("domain")
        session = domain_entry.get("session") or {}
        session_header_names = {k.lower() for k in session.keys()}

        if not domain or not session_header_names:
            continue

        domain_traffic = [r for r in traffic if record_domain(r) == domain]
        unique_traffic = dedup_latest_by_knumal_req(domain_traffic)

        for record in unique_traffic:
            if get_request_header_names(record.get("request", "")) & session_header_names:
                record = dict(record)
                record["_user"] = user
                result.append(record)

    return result


def load_unique_records(path: str) -> List[Dict[str, Any]]:

    candidates = load_candidates_from_file(path)

    unique_records = []
    for cand in candidates:
        unique_records.extend(filter_candidate_traffic(cand))

    return unique_records


# ==============================
# JWT AWARENESS
# ==============================

def _b64_decode_segment(segment: str) -> bytes:

    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def get_session_headers_for_host(record: Dict[str, Any]) -> Dict[str, str]:
    """Looks up the session headers (authorization, x-authorization, cookie, ...)
    that belong to this record's user for this record's host, from the
    'domains' block produced by knumal-2 (user.domains[].session)."""

    domain = record_domain(record)
    domains = record.get("_user", {}).get("domains", [])

    for domain_entry in domains:
        if domain_entry.get("domain") == domain:
            return dict(domain_entry.get("session") or {})

    return {}


def _strip_bearer_prefix(value: str) -> str:

    if value.lower().startswith("bearer "):
        return value[7:].strip()
    return value.strip()


def is_jwt_expired(token: str) -> Optional[bool]:

    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        payload = json.loads(_b64_decode_segment(parts[1]))
    except Exception:
        return None

    exp = payload.get("exp")
    if exp is None:
        return None

    return datetime.now(timezone.utc).timestamp() > exp


def any_session_value_expired(session_headers: Dict[str, str]) -> bool:
    """A session can carry multiple credentials (authorization, x-authorization,
    cookie, custom 'token' headers, ...). If any one of them is a JWT that has
    already expired, the whole session is considered unusable for replay."""

    for value in session_headers.values():
        token = _strip_bearer_prefix(str(value))
        expired = is_jwt_expired(token)
        if expired:
            return True

    return False


# ==============================
# HTTP REQUEST PARSING (for replay)
# ==============================

def parse_raw_request_for_replay(raw_request: str):

    raw_request = raw_request.replace("\r\n", "\n")
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


def hash_response_body(body: str) -> str:

    return hashlib.sha256(body.strip().encode(errors="ignore")).hexdigest()


def extract_replay_response_body(response: "requests.Response") -> str:
    """Reads the response body as raw bytes (instead of response.text, which
    auto-decodes based on charset), then decodes manually with errors="ignore"
    so the extraction matches extract_response_body() in knumal-1 (which works
    on the raw capture)."""

    return response.content.decode(errors="ignore")


# ==============================
# REPLAY
# ==============================

def replay_request(record: Dict[str, Any], session: Optional[requests.Session] = None) -> "ReplayResult":
    """Returns a ReplayResult with either a fingerprint or a skip reason."""

    raw_request = record.get("request", "")
    method, path, headers, body = parse_raw_request_for_replay(raw_request)

    if not method or not path:
        return ReplayResult(None, "malformed_request")

    session_headers = get_session_headers_for_host(record)
    if any_session_value_expired(session_headers):
        return ReplayResult(None, "jwt_expired", session_headers=session_headers)

    protocol = record.get("protocol", "https")
    host = record.get("host")
    port = record.get("port")

    default_port = {"https": "443", "http": "80"}.get(protocol)
    netloc = host if not port or port == default_port else f"{host}:{port}"
    url = f"{protocol}://{netloc}{path}"

    headers.pop("Host", None)
    headers.pop("Content-Length", None)

    for key in list(headers):
        if key.lower() in (sk.lower() for sk in session_headers):
            headers.pop(key)
    headers.update(session_headers)

    ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE")
    verify = ca_bundle if ca_bundle else False

    if not verify:
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    sender = session or requests

    try:
        response = sender.request(
            method=method,
            url=url,
            headers=headers,
            data=body.encode() if body else None,
            timeout=REQUEST_TIMEOUT,
            verify=verify,
        )
    except requests.exceptions.Timeout as e:
        return ReplayResult(None, f"{type(e).__name__}: {e}", is_timeout=True, session_headers=session_headers)
    except requests.RequestException as e:
        return ReplayResult(None, f"{type(e).__name__}: {e}", session_headers=session_headers)

    if response.status_code in RATE_LIMIT_STATUS_CODES:
        return ReplayResult(None, f"rate_limited_status_{response.status_code}", is_timeout=True, session_headers=session_headers)

    return ReplayResult(hash_response_body(extract_replay_response_body(response)), None, session_headers=session_headers)


# ==============================
# DOMAIN SELECTION (pre-replay)
# ==============================

def domain_to_filename_suffix(domain: str) -> str:

    return domain.replace(".", "_")


RED = "\033[91m"
RESET = "\033[0m"


def build_domain_stats(unique_records: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:

    by_domain: Dict[str, Dict[str, int]] = {}

    for record in unique_records:
        host = record.get("host", "unknown")
        user_login = record.get("_user", {}).get("user_login", "unknown")
        by_domain.setdefault(host, {})
        by_domain[host][user_login] = by_domain[host].get(user_login, 0) + 1

    return by_domain


def render_domain_menu(domains: List[str], by_domain: Dict[str, Dict[str, int]], selected: List[str]) -> None:

    print("Pre-Replay Domain Summary")
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


def print_pre_replay_summary(unique_records: List[Dict[str, Any]]) -> List[str]:
    """Return the list of domains in the order they'll be numbered in the menu."""

    by_domain = build_domain_stats(unique_records)
    return sorted(by_domain.keys(), key=lambda h: sum(by_domain[h].values()), reverse=True)


def _domain_selection_prompt(domains: List[str], selected: List[str]) -> str:

    if selected:
        return "Add another domain? [number, blank to start replay, or 'all']: "
    return f"Select domain(s) to replay [1-{len(domains)}, or 'all']: "


def _toggle_domain_selection(domains: List[str], selected: List[str], choice: str) -> None:

    host = domains[int(choice) - 1]
    if host in selected:
        selected.remove(host)
    else:
        selected.append(host)


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
            _toggle_domain_selection(domains, selected, choice)
            continue

        print("[!] Invalid choice, try again.")


# ==============================
# REPLAY CONFIRMATION PROMPT
# ==============================

def confirm_replay(total_unique: int) -> Optional[Dict[str, Any]]:

    print(f"\n[?] Ready to replay {total_unique} unique request(s) against the live target.")

    while True:
        answer = input("Proceed with replay? [Yes/No]: ").strip().lower()
        if answer in ("yes", "y"):
            break
        if answer in ("no", "n"):
            return None
        print("[!] Please answer Yes or No.")

    while True:
        raw = input("Number of parallel threads [10]: ").strip()
        if raw == "":
            threads = 10
            break
        if raw.isdigit() and int(raw) >= 1:
            threads = int(raw)
            break
        print("[!] Please enter a positive integer.")

    while True:
        raw = input("Delay between requests per thread (ms) [1000]: ").strip()
        if raw == "":
            delay_ms = 1000
            break
        if raw.isdigit() and int(raw) >= 0:
            delay_ms = int(raw)
            break
        print("[!] Please enter a non-negative integer.")

    return {"threads": threads, "delay_ms": delay_ms}


# ==============================
# CLASSIFY
# ==============================

def _build_classified_record(record: Dict[str, Any], fingerprint: str, session_headers: Dict[str, str]) -> Dict[str, Any]:

    old_fingerprint = record.get("knumal_resp")
    baseline_status = record.get("http_status", "")

    if baseline_status.startswith(("4", "5")):
        classification = "baseline_error"
    elif fingerprint == old_fingerprint:
        classification = "simple"
    else:
        classification = "ambiguous"

    enriched = {}
    for key, value in record.items():
        enriched[key] = value
        if key == "request":
            enriched["session_detected"] = [{k: v} for k, v in session_headers.items()]

    enriched["classification"] = classification
    enriched["replay_resp"] = fingerprint
    return enriched


def render_progress_bar(completed: int, total: int, pool_size: int, width: int = 30) -> None:

    fraction = completed / total if total else 1.0
    filled = int(width * fraction)
    bar = "#" * filled + "-" * (width - filled)

    end = "\n" if completed == total else ""
    print(f"\r    [{bar}] {completed}/{total} (pool size: {pool_size})", end=end, flush=True)


def _run_replay_round(pending: List[Dict[str, Any]], pool_size: int, delay_ms: int,
                       progress: Dict[str, Any], lock: threading.Lock):
    """Runs one ThreadPoolExecutor pass over `pending`. Returns (classified, next_round, had_timeout).

    Rate-limit/timeout hits retry indefinitely WHILE the pool can still shrink. Once
    pool_size has bottomed out at MIN_THREADS, they're capped at MAX_ATTEMPTS too
    (there's nothing left to shrink to, so an unlimited retry would hang forever
    against a target that's simply down)."""

    thread_local = threading.local()

    def get_session() -> requests.Session:
        if not hasattr(thread_local, "session"):
            thread_local.session = requests.Session()
        return thread_local.session

    def try_once(record: Dict[str, Any]) -> ReplayResult:
        result = replay_request(record, session=get_session())
        if delay_ms > 0:
            time.sleep(delay_ms / 1000)
        return result

    classified = []
    next_round = []
    had_timeout = False
    pool_at_floor = pool_size <= MIN_THREADS

    with ThreadPoolExecutor(max_workers=pool_size) as executor:
        futures = {executor.submit(try_once, item["record"]): item for item in pending}

        for future in futures:
            item = futures[future]
            result = future.result()

            with lock:
                progress["completed"] += 1
                render_progress_bar(progress["completed"], progress["total"], pool_size)

            if result.fingerprint is not None:
                classified.append(_build_classified_record(item["record"], result.fingerprint, result.session_headers))
                continue

            had_timeout = had_timeout or result.is_timeout

            if result.is_timeout and not pool_at_floor:
                # Still room to shrink: retry indefinitely, don't burn an attempt.
                next_round.append(item)
                with lock:
                    progress["completed"] -= 1
                continue

            item["attempt"] += 1
            if item["attempt"] < MAX_ATTEMPTS:
                next_round.append(item)
                with lock:
                    progress["completed"] -= 1
            else:
                with lock:
                    progress["skipped"] += 1
                    progress["skipped_records"].append({
                        "record": item["record"],
                        "skip_reason": result.skip_reason,
                    })

    return classified, next_round, had_timeout


def _shrink_pool_if_needed(pool_size: int, had_timeout: bool) -> int:

    if not had_timeout or pool_size <= MIN_THREADS:
        return pool_size

    new_pool_size = max(MIN_THREADS, int(pool_size * POOL_SHRINK_FACTOR))
    if new_pool_size != pool_size:
        print(f"\n    [!] Timeout detected, shrinking parallel pool: {pool_size} -> {new_pool_size}", flush=True)

    return new_pool_size


def classify_records(unique_records: List[Dict[str, Any]], threads: int, delay_ms: int) -> List[Dict[str, Any]]:

    lock = threading.Lock()
    progress = {"completed": 0, "skipped": 0, "total": len(unique_records), "skipped_records": []}

    classified = []
    pending = [{"record": r, "attempt": 0} for r in unique_records]
    pool_size = threads

    while pending:
        round_classified, pending, had_timeout = _run_replay_round(pending, pool_size, delay_ms, progress, lock)
        classified.extend(round_classified)

        if pending:
            pool_size = _shrink_pool_if_needed(pool_size, had_timeout)

    print(f"[+] Skipped after {MAX_ATTEMPTS} failed attempts: {progress['skipped']}")

    return classified, progress["skipped_records"]


# ==============================
# TERMINAL OUTPUT
# ==============================

def print_summary(classified: List[Dict[str, Any]]):

    by_host: Dict[str, Dict[str, int]] = {}
    by_host_user: Dict[str, Dict[str, Dict[str, int]]] = {}

    empty_counts = {"simple": 0, "ambiguous": 0, "baseline_error": 0}

    for record in classified:
        host = record.get("host", "unknown")
        user_login = record.get("_user", {}).get("user_login", "unknown")
        classification = record["classification"]

        by_host.setdefault(host, dict(empty_counts))
        by_host[host][classification] += 1

        by_host_user.setdefault(host, {}).setdefault(user_login, dict(empty_counts))
        by_host_user[host][user_login][classification] += 1

    print("Replay Classification Summary")
    print("=" * 70)

    for idx, (host, counts) in enumerate(by_host.items(), start=1):
        total = counts["simple"] + counts["ambiguous"] + counts["baseline_error"]
        users = by_host_user[host]

        print(f"{idx}. {host} ({total} endpoint)")
        print(f"   a. simple         : {counts['simple']}")
        print(f"   b. ambiguous      : {counts['ambiguous']}")
        print(f"   c. baseline_error : {counts['baseline_error']}")
        print(f"   Total users       : {len(users)}")

        for user_login, user_counts in users.items():
            user_total = user_counts["simple"] + user_counts["ambiguous"] + user_counts["baseline_error"]
            print(f"     - {user_login} ({user_total} endpoint): simple={user_counts['simple']}, ambiguous={user_counts['ambiguous']}, baseline_error={user_counts['baseline_error']}")

    print("=" * 70)


# ==============================
# SKIPPED REPORT (timeout / rate limit / etc.)
# ==============================

def print_skipped(skipped_records: List[Dict[str, Any]]):

    print(f"[+] Total skipped (timeout/rate-limit/error after {MAX_ATTEMPTS} attempts): {len(skipped_records)}")

    if not skipped_records:
        return

    for item in skipped_records:
        record = item["record"]
        host = record.get("host", "unknown")
        user_login = record.get("_user", {}).get("user_login", "unknown")
        endpoint = record.get("endpoint", UNKNOWN_ENDPOINT)
        reason = item.get("skip_reason") or "unknown"
        print(f"    - [{host}] {user_login}: {endpoint} ({reason})")


# ==============================
# AMBIGUOUS REPORT
# ==============================

def print_ambiguous(classified: List[Dict[str, Any]]):

    ambiguous = [r for r in classified if r["classification"] == "ambiguous"]

    print(f"[+] Total ambiguous (request & response changed during replay): {len(ambiguous)}")

    if not ambiguous:
        return

    for record in ambiguous:
        host = record.get("host", "unknown")
        user_login = record.get("_user", {}).get("user_login", "unknown")
        endpoint = record.get("endpoint", UNKNOWN_ENDPOINT)
        print(f"    - [{host}] {user_login}: {endpoint}")


# ==============================
# CLUSTER OUTPUT (host -> user -> traffic)
# ==============================

def build_cluster_output(classified: List[Dict[str, Any]]) -> Dict[str, Any]:

    hosts: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

    for record in classified:
        host = record.get("host", "unknown")
        user_login = record.get("_user", {}).get("user_login", "unknown")

        clean_record = {k: v for k, v in record.items() if k not in ("response", "_user")}

        hosts.setdefault(host, {}).setdefault(user_login, []).append(clean_record)

    cluster = []
    for host, users in hosts.items():
        user_children = [
            {"user": user_login, "children": records}
            for user_login, records in users.items()
        ]
        cluster.append({"host": host, "children": user_children})

    return {"cluster": cluster}


# ==============================
# MAIN
# ==============================

def main():

    files = find_candidate_files(".")

    if not files:
        print("[!] No candidate file (root key 'candidate') found.")
        return

    selected_file = choose_candidate_file(files)
    print(f"[+] Selected: {selected_file}")

    unique_records = load_unique_records(selected_file)
    print(f"[+] Total unique requests (matching domain & session header filter): {len(unique_records)}")
    print()

    by_domain = build_domain_stats(unique_records)
    domains = print_pre_replay_summary(unique_records)
    selected_domains = choose_domains(domains, by_domain)
    print(f"[+] Selected domain(s): {', '.join(selected_domains)}")
    print()

    unique_records = [r for r in unique_records if r.get("host") in selected_domains]

    counts_by_user: Dict[str, int] = {}
    for record in unique_records:
        user_login = record.get("_user", {}).get("user_login", "unknown")
        counts_by_user[user_login] = counts_by_user.get(user_login, 0) + 1

    print("[+] Breakdown by user:")
    for user_login, count in sorted(counts_by_user.items(), key=lambda kv: kv[1], reverse=True):
        print(f"    - {user_login}: {count}")

    options = confirm_replay(len(unique_records))
    if options is None:
        print("[!] Replay cancelled by user.")
        return

    print("[+] Replaying...")
    classified, skipped_records = classify_records(unique_records, threads=options["threads"], delay_ms=options["delay_ms"])

    print(f"[+] Total successfully replayed & classified: {len(classified)}")
    print()

    print_summary(classified)
    print()

    print_ambiguous(classified)
    print()

    print_skipped(skipped_records)
    print()

    cluster_output = build_cluster_output(classified)

    if selected_domains == domains:
        suffix = "all"
    else:
        suffix = "_".join(domain_to_filename_suffix(d) for d in selected_domains)

    output_path = f"{suffix}_baseline.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(cluster_output, f, indent=4, ensure_ascii=False)

    print(f"\n[+] Output saved to {output_path}")


if __name__ == "__main__":
    main()
