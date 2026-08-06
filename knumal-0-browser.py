#!/usr/bin/env python3
import argparse
import glob
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from playwright.sync_api import sync_playwright

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# Headers that are NEVER session credentials (transport/negotiation/browser
# metadata, CORS, proxy/infra, caching, etc). Anything NOT in this list is
# treated as a session header candidate -- broader than a fixed keyword/prefix
# list, so it also catches custom headers (e.g. "X-Nunu-Ticket") that don't
# match any known naming convention.
HEADER_EXCLUSION_LIST = {
    # General
    "host", "connection", "proxy-connection", "keep-alive", "content-length",
    "content-type", "content-encoding", "content-language", "content-md5",
    "transfer-encoding", "te", "trailer", "upgrade", "via", "date", "pragma",
    "cache-control", "expect", "max-forwards",
    # Content negotiation
    "accept", "accept-charset", "accept-encoding", "accept-language", "accept-datetime",
    # Conditional
    "if-match", "if-none-match", "if-modified-since", "if-unmodified-since",
    "if-range", "range",
    # Client hints
    "sec-ch-ua", "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list", "sec-ch-ua-mobile", "sec-ch-ua-model",
    "sec-ch-ua-platform", "sec-ch-ua-platform-version",
    "sec-ch-prefers-color-scheme", "sec-ch-prefers-reduced-motion",
    "sec-ch-viewport-width", "sec-ch-device-memory", "sec-ch-dpr",
    "sec-ch-width", "sec-ch-viewport-height",
    # Fetch metadata
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user",
    "sec-fetch-storage-access",
    # Navigation
    "referer", "referrer-policy", "origin", "origin-agent-cluster",
    "upgrade-insecure-requests",
    # Browser identification
    "user-agent", "dnt", "sec-gpc", "x-client-data", "x-requested-with",
    # Priority/connection hints
    "priority", "save-data", "downlink", "ect", "rtt",
    # CORS
    "access-control-allow-origin", "access-control-allow-methods",
    "access-control-allow-headers", "access-control-allow-credentials",
    "access-control-expose-headers", "access-control-max-age",
    "access-control-request-method", "access-control-request-headers",
    # Response metadata
    "server", "vary", "etag", "last-modified", "expires",
    "content-disposition", "content-security-policy", "x-content-type-options",
    "x-frame-options", "x-xss-protection", "strict-transport-security",
    "timing-allow-origin", "cross-origin-opener-policy",
    "cross-origin-embedder-policy", "cross-origin-resource-policy",
    # Proxy/infra
    "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
    "x-forwarded-port", "x-real-ip", "forwarded", "cf-ray",
    "cf-connecting-ip", "x-amz-cf-id", "x-cache", "x-served-by",
    # Misc
    "alt-svc", "link", "location", "retry-after", "warning", "allow",
}

# Headers that must not be replayed manually via `requests`
NON_REPLAYABLE_HEADERS = {"host", "content-length", "connection", "accept-encoding"}

SESSIONS_DIR = "sessions"


def strip_non_replayable_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Remove NON_REPLAYABLE_HEADERS and HTTP/2 pseudo-headers (":authority",
    ":method", ":path", ":scheme" -- returned by Playwright's all_headers()
    for h2 requests). `requests` rejects header names containing ":" outright
    (InvalidHeader), which would make EVERY replay for an h2 domain fail
    identically regardless of the real session header -- silently hiding the
    real session."""

    return {
        k: v for k, v in headers.items()
        if k.lower() not in NON_REPLAYABLE_HEADERS and not k.startswith(":")
    }


def extract_domain(url: str) -> str:
    """Extract host[:port] from a URL, dropping scheme and path.
    Works even without a scheme (e.g. "malis.local:8443/x" or "malis.local"),
    since urlparse misreads those as scheme:path without one.
    e.g. "https://abc.def.malis.local:8443/x" -> "abc.def.malis.local:8443" """

    candidate = url if "//" in url else f"//{url}"
    netloc = urlparse(candidate).netloc
    return netloc or url.rstrip("/")


def short_hash_id(user_login: str, url: str) -> str:
    domain = extract_domain(url)
    url_digest = hashlib.sha256(domain.encode("utf-8")).hexdigest()
    user_digest = hashlib.sha256(user_login.encode("utf-8")).hexdigest()
    return f"knu-mal_{url_digest[:2] + url_digest[-2:] + user_digest[:3] + user_digest[-3:]}"


def build_user_agent(user_login: str, url: str) -> str:
    return f"{DEFAULT_USER_AGENT}_{short_hash_id(user_login, url)}"


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b or b"").hexdigest()


def parse_cookie_header(cookie_value: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not cookie_value:
        return out
    for part in cookie_value.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def build_cookie_header(cookies: Dict[str, str]) -> str:
    return "; ".join(f"{k}={v}" for k, v in sorted(cookies.items(), key=lambda x: x[0].lower()))


def detect_session_header_candidates(headers: Dict[str, str]) -> List[str]:
    """Any header NOT in HEADER_EXCLUSION_LIST is a session candidate
    (exclusion-based, so unknown/custom credential headers are caught too --
    not just names matching a fixed keyword list).

    HTTP/2 pseudo-headers (":authority", ":method", ":path", ":scheme" --
    returned by Playwright's all_headers() for h2 requests) are always
    excluded: they're transport-level routing info (":authority" is just the
    Host header's h2 equivalent), never session credentials."""

    return sorted({
        k.lower() for k in headers
        if k.lower() not in HEADER_EXCLUSION_LIST and not k.startswith(":")
    })


def send_request(method: str, url: str, headers: Dict[str, str], timeout_sec: int = 10, body: str = "") -> Tuple[int, bytes]:
    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=body.encode("utf-8", errors="ignore") if body else None,
            timeout=timeout_sec,
            allow_redirects=True,
            verify=False,
        )
        return resp.status_code, resp.content or b""
    except Exception as e:
        err = f"__REQUEST_ERROR__ {type(e).__name__}: {e}".encode("utf-8", errors="ignore")
        return 0, err


def group_requests_by_endpoint_all_occurrences(requests_log: List[Dict[str, Any]]) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
    """
    Group ALL occurrences (not just first-seen) per (method, url-without-query)
    endpoint, so callers can sort by time and pick the most recent ones.
    """
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for r in requests_log:
        parsed = urlparse(r["url"])
        endpoint_key = (r["method"], f"{parsed.scheme}://{parsed.netloc}{parsed.path}")
        grouped.setdefault(endpoint_key, []).append(r)
    return grouped


def count_endpoint_hits(requests_log: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Count how many times each domain was hit across all captured requests.
    """
    hits: Dict[str, int] = {}
    for r in requests_log:
        domain = urlparse(r["url"]).netloc
        hits[domain] = hits.get(domain, 0) + 1
    return hits


def group_endpoints_by_domain_all(grouped: Dict[Tuple[str, str], List[Dict[str, Any]]]) -> Dict[str, List[Tuple[Tuple[str, str], List[Dict[str, Any]]]]]:
    by_domain: Dict[str, List[Tuple[Tuple[str, str], List[Dict[str, Any]]]]] = {}
    for (method, url), occurrences in grouped.items():
        domain = urlparse(url).netloc
        by_domain.setdefault(domain, []).append(((method, url), occurrences))
    return by_domain


def pop_header_ci(headers: Dict[str, str], name_lower: str) -> Optional[str]:
    """Remove a header from `headers` matching `name_lower` case-insensitively
    (candidate names from detect_session_header_candidates are always
    lowercase, but the raw headers dict keeps its original casing, e.g.
    "Cookie" -- a plain dict.pop("cookie") would silently miss it)."""

    for key in list(headers):
        if key.lower() == name_lower:
            return headers.pop(key)
    return None


def get_header_ci(headers: Dict[str, str], name_lower: str) -> str:

    for key, value in headers.items():
        if key.lower() == name_lower:
            return value
    return ""


def find_required_headers_for_endpoint(
    method: str, url: str, headers: Dict[str, str], timeout_sec: int, body: str = "",
    header_progress_cb=None,
) -> Dict[str, str]:
    """
    For a single endpoint: strip candidate headers one by one, replay the real request
    (including its original body, so POST/PUT/PATCH endpoints are tested faithfully),
    and compare response body hash against baseline to decide required vs optional.

    header_progress_cb(name, is_required, detail), if given, is called after
    every individual header/cookie test so the UI can report each trial
    ("testing header X ... REQUIRED/NOT REQUIRED") instead of a single opaque
    per-endpoint result.
    """
    candidates = detect_session_header_candidates(headers)
    if not candidates:
        return {}

    baseline_status, baseline_content = send_request(method, url, headers, timeout_sec, body=body)
    baseline_hash = sha256_bytes(baseline_content)

    working_headers = dict(headers)
    required = {}

    for h in candidates:
        test_headers = dict(working_headers)
        pop_header_ci(test_headers, h)

        status, content = send_request(method, url, test_headers, timeout_sec, body=body)
        test_hash = sha256_bytes(content)

        is_required = test_hash != baseline_hash
        if is_required:
            required[h] = get_header_ci(working_headers, h)
        else:
            pop_header_ci(working_headers, h)

        if header_progress_cb:
            header_progress_cb(h, is_required, f"status {status}")

    # Cookie minimization: break down which cookie names actually matter
    if "cookie" in required:
        cookie_dict = parse_cookie_header(required["cookie"])
        required_cookies = {}
        remaining_cookies = dict(cookie_dict)

        base_headers_no_cookie = {k: v for k, v in working_headers.items() if k.lower() != "cookie"}
        base_status, base_content = send_request(
            method, url, {**base_headers_no_cookie, "cookie": build_cookie_header(remaining_cookies)}, timeout_sec, body=body
        )
        base_hash = sha256_bytes(base_content)

        for cname in cookie_dict:
            trial = dict(remaining_cookies)
            trial.pop(cname, None)
            test_headers = dict(base_headers_no_cookie)
            if trial:
                test_headers["cookie"] = build_cookie_header(trial)

            status, content = send_request(method, url, test_headers, timeout_sec, body=body)
            test_hash = sha256_bytes(content)

            is_required = test_hash != base_hash
            if is_required:
                required_cookies[cname] = cookie_dict[cname]
            else:
                remaining_cookies.pop(cname, None)

            if header_progress_cb:
                header_progress_cb(f"cookie:{cname}", is_required, f"status {status}")

        if required_cookies:
            required["cookie"] = build_cookie_header(required_cookies)
        else:
            required.pop("cookie", None)

    return required


# ==============================
# DOMAIN SELECTION (interactive, before analysis)
# ==============================

def render_domain_selection_menu(domains: List[str], hit_counts: Dict[str, int], selected: List[str]) -> None:

    print("\nDomain Summary")
    print("=" * 70)
    for idx, domain in enumerate(domains, start=1):
        label = f"{idx}. {domain} ({hit_counts.get(domain, 0)} hit)"
        if domain in selected:
            label = f"\033[91m{label} [selected]\033[0m"
        print(label)
    print("=" * 70)


def choose_domains_for_analysis(domains: List[str], hit_counts: Dict[str, int]) -> List[str]:

    selected: List[str] = []

    while True:
        render_domain_selection_menu(domains, hit_counts, selected)

        if selected:
            prompt = "Add another domain? [number, blank to continue, or 'all']: "
        else:
            prompt = f"Select domain(s) to check for session [1-{len(domains)}, or 'all']: "

        choice = input(prompt).strip().lower()

        if choice == "":
            if selected:
                return selected
            print("[!] No domain selected yet.")
            continue

        if choice == "all":
            return domains

        if choice.isdigit() and 1 <= int(choice) <= len(domains):
            domain = domains[int(choice) - 1]
            if domain in selected:
                selected.remove(domain)
            else:
                selected.append(domain)
            continue

        print("[!] Invalid choice, try again.")


# ==============================
# SESSION HEADER ANALYSIS (sampled: last N endpoints per domain, majority vote)
# ==============================

RATE_LIMIT_STATUS_CODES = {429, 500, 502, 503, 504}


def endpoint_time(occurrence: Dict[str, Any]) -> str:
    return occurrence.get("time") or ""


def find_endpoints_with_candidates(
    endpoints: List[Tuple[Tuple[str, str], List[Dict[str, Any]]]]
) -> List[Tuple[Tuple[str, str], Dict[str, Any], List[str]]]:
    """For each unique (method, url) endpoint, use its most recent occurrence
    to cheaply (no network call) detect session header candidates by name.
    Returns only endpoints that have at least one candidate, each paired with
    its most recent occurrence and the candidate list."""

    with_candidates = []
    for endpoint_key, occurrences in endpoints:
        latest = max(occurrences, key=endpoint_time)
        headers = strip_non_replayable_headers(latest["headers"])
        candidates = detect_session_header_candidates(headers)
        if candidates:
            with_candidates.append((endpoint_key, latest, candidates))

    return with_candidates


def replay_endpoint_sample(
    endpoint_key: Tuple[str, str], sample: Dict[str, Any], timeout_sec: int,
    header_progress_cb=None,
) -> Tuple[Optional[Dict[str, str]], bool]:
    """Replay one endpoint sample. Returns (required_headers, is_rate_limited).
    required_headers is None if the attempt hit a rate-limit-like error."""

    method, url = endpoint_key
    headers = strip_non_replayable_headers(sample["headers"])
    body = sample.get("body") or ""

    baseline_status, _ = send_request(method, url, headers, timeout_sec, body=body)
    if baseline_status in RATE_LIMIT_STATUS_CODES:
        return None, True

    required = find_required_headers_for_endpoint(
        method, url, headers, timeout_sec, body=body, header_progress_cb=header_progress_cb
    )
    return required, False


def sample_and_replay_domain(
    endpoints: List[Tuple[Tuple[str, str], List[Dict[str, Any]]]],
    sample_size: int,
    timeout_sec: int,
    delay_ms: int,
    max_replacement_attempts: int,
    progress_cb,
    header_progress_cb=None,
) -> Optional[List[Dict[str, str]]]:
    """Pick the `sample_size` most recently seen endpoints (among those with
    header candidates) for a domain, replay each with a delay between
    requests, and swap in the next-closest-in-time replacement whenever a
    rate-limit-like (5xx/429) response is hit. Gives up (returns None, meaning
    "skip this domain") after `max_replacement_attempts` replacements without
    a clean run."""

    with_candidates = find_endpoints_with_candidates(endpoints)
    if not with_candidates:
        return []

    with_candidates.sort(key=lambda item: endpoint_time(item[1]), reverse=True)

    chosen = with_candidates[:sample_size]
    pool = with_candidates[sample_size:]

    results: List[Dict[str, str]] = []
    replacement_attempts = 0
    i = 0

    while i < len(chosen):
        endpoint_key, sample, _candidates = chosen[i]
        progress_cb(endpoint_key)

        required, rate_limited = replay_endpoint_sample(endpoint_key, sample, timeout_sec, header_progress_cb=header_progress_cb)

        if rate_limited:
            replacement_attempts += 1
            if replacement_attempts > max_replacement_attempts or not pool:
                return None  # give up on this domain

            chosen[i] = pool.pop(0)
            if delay_ms > 0:
                time.sleep(delay_ms / 1000)
            continue

        results.append(required)
        i += 1

        if delay_ms > 0:
            time.sleep(delay_ms / 1000)

    return results


def majority_vote_session(per_endpoint_required: List[Dict[str, str]]) -> Dict[str, str]:
    """Combine required-header results from N replayed endpoints into one
    session dict, keeping a header only if it was required in a STRICT
    majority (> N/2) of the successful attempts. Cookie names are voted on
    individually (not the whole Cookie header as one unit)."""

    n = len(per_endpoint_required)
    if n == 0:
        return {}

    header_votes: Dict[str, int] = {}
    header_values: Dict[str, str] = {}
    cookie_votes: Dict[str, int] = {}
    cookie_values: Dict[str, str] = {}

    for required in per_endpoint_required:
        for h, v in required.items():
            if h == "cookie":
                for cname, cval in parse_cookie_header(v).items():
                    cookie_votes[cname] = cookie_votes.get(cname, 0) + 1
                    cookie_values[cname] = cval
            else:
                header_votes[h] = header_votes.get(h, 0) + 1
                header_values[h] = v

    session: Dict[str, str] = {}
    for h, votes in header_votes.items():
        if votes > n / 2:
            session[h] = header_values[h]

    required_cookies = {c: v for c, v in cookie_values.items() if cookie_votes[c] > n / 2}
    if required_cookies:
        session["cookie"] = build_cookie_header(required_cookies)

    return session


def analyze_session_headers(
    requests_log: List[Dict[str, Any]],
    timeout_sec: int,
    selected_domains: List[str],
    sample_size: int = 3,
    delay_ms: int = 1000,
    max_replacement_attempts: int = 10,
) -> List[Dict[str, Any]]:
    """
    Behavior-based session discovery: for each selected domain, sample the
    `sample_size` most recently seen endpoints that have session header
    candidates, replay each (with a delay to avoid rate limits, swapping in
    replacements on 5xx), and combine the results via majority vote.
    """
    grouped = group_requests_by_endpoint_all_occurrences(requests_log)
    by_domain = group_endpoints_by_domain_all(grouped)
    hit_counts = count_endpoint_hits(requests_log)

    results = []

    for domain in selected_domains:
        endpoints = by_domain.get(domain, [])
        print(f"\n[*] Analyzing domain: {domain}")

        def progress_cb(endpoint_key, _domain=domain):
            print(f"\n  -> Endpoint: {endpoint_key[0]} {endpoint_key[1]}")

        def header_progress_cb(name, is_required, detail):
            verdict = "REQUIRED (session)" if is_required else "not required"
            print(f"       testing header '{name}' ... {verdict} ({detail})")

        per_endpoint_required = sample_and_replay_domain(
            endpoints, sample_size, timeout_sec, delay_ms, max_replacement_attempts,
            progress_cb, header_progress_cb=header_progress_cb,
        )

        if per_endpoint_required is None:
            print(f"    [!] Skipping domain {domain}: repeated rate-limit errors.")
            results.append({"domain": domain, "hit_endpoint": hit_counts.get(domain, 0), "session": {}})
            continue

        domain_session = majority_vote_session(per_endpoint_required)

        results.append({
            "domain": domain,
            "hit_endpoint": hit_counts.get(domain, 0),
            "session": domain_session,
        })

    results.sort(key=lambda r: r["hit_endpoint"], reverse=True)
    return results


# ==============================
# SESSION FILE SELECTION (--session)
# ==============================

def list_session_files() -> List[str]:
    if not os.path.isdir(SESSIONS_DIR):
        return []
    return sorted(glob.glob(os.path.join(SESSIONS_DIR, "*.json")))


def choose_session_file() -> str:
    files = list_session_files()
    if not files:
        print(f"[!] Tidak ada session ditemukan di folder '{SESSIONS_DIR}/'.")
        raise SystemExit(1)

    print("\nSession tersedia:")
    for i, f in enumerate(files, 1):
        print(f"{i}. {f}")

    while True:
        raw = input("\nPilih session (nomor): ").strip()
        try:
            n = int(raw)
            if 1 <= n <= len(files):
                return files[n - 1]
        except ValueError:
            pass
        print(f"Masukkan angka 1..{len(files)}")


def load_session_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(description="Open a Playwright-controlled browser through a proxy and record session traffic.")
    parser.add_argument("-u", "--url", help="URL to open")
    parser.add_argument("-p", "--proxy", help="Proxy server, e.g. http://127.0.0.1:8080")
    parser.add_argument("-a", "--agent", help="User login / username used as the login identifier")
    parser.add_argument("-o", "--output", default=None, help="Output JSON path (default: sessions/<user_login>_<timestamp>.json)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout (seconds) for header impact replay requests")
    parser.add_argument("--skip-analysis", action="store_true", help="Skip behavior-based session header analysis")
    parser.add_argument("--session", action="store_true", help="Resume an existing logged-in session instead of starting fresh")
    args = parser.parse_args()

    session_file_path = None
    previous_session = None
    storage_state_input = None

    if args.session:
        session_file_path = choose_session_file()
        previous_session = load_session_file(session_file_path)
        storage_state_input = previous_session.get("storage_state")

        url = args.url or previous_session.get("url")
        proxy = args.proxy or previous_session.get("proxy")
        user_login = args.agent or previous_session.get("user_login")
        user_agent = previous_session.get("user_agent") or build_user_agent(user_login, url)

        if not url or not proxy or not user_login:
            print("[!] Session lama tidak memiliki url/proxy/user_login yang lengkap dan tidak di-override via CLI.")
            raise SystemExit(1)
    else:
        if not args.url or not args.proxy or not args.agent:
            print("[!] -u/--url, -p/--proxy, dan -a/--agent wajib diisi jika --session tidak digunakan.")
            raise SystemExit(1)
        url = args.url
        proxy = args.proxy
        user_login = args.agent
        user_agent = build_user_agent(user_login, url)

    os.makedirs(SESSIONS_DIR, exist_ok=True)
    output_path = session_file_path or args.output or os.path.join(
        SESSIONS_DIR, f"{user_login}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    )

    requests_log = []

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=False,
            proxy={"server": proxy},
        )
        context_kwargs = {
            "user_agent": user_agent,
            "ignore_https_errors": True,
        }
        if storage_state_input:
            context_kwargs["storage_state"] = storage_state_input

        context = browser.new_context(**context_kwargs)
        page = context.new_page()

        def on_request(request):
            try:
                headers = request.all_headers()
            except Exception:
                headers = request.headers

            try:
                body = request.post_data or ""
            except Exception:
                # post_data decodes as strict UTF-8 internally and raises on
                # binary/non-UTF-8 payloads (e.g. file uploads). Fall back to
                # the raw buffer, decoded leniently.
                try:
                    buf = request.post_data_buffer
                    body = buf.decode("utf-8", errors="ignore") if buf else ""
                except Exception:
                    body = ""

            requests_log.append({
                "time": datetime.now(timezone.utc).isoformat(),
                "method": request.method,
                "url": request.url,
                "headers": headers,
                "resource_type": request.resource_type,
                "body": body,
            })

        page.on("request", on_request)

        print(f"[+] Proxy: {proxy}")
        print(f"[+] User-Agent: {user_agent}")
        if args.session:
            print(f"[+] Resumed session: {session_file_path}")

        print("[*] Browser will open in:")
        for remaining in (3, 2, 1):
            print(f"    {remaining}..")
            time.sleep(1)

        page.goto(url)

        print(f"[+] Browser opened at {url}")
        input("[*] Press Enter when you are done to close the browser and save the session...\n")

        storage_state = context.storage_state()

        browser.close()

    # Merge requests with previous session's requests (if resuming)
    if previous_session:
        combined_requests = (previous_session.get("requests") or []) + requests_log
    else:
        combined_requests = requests_log

    session_analysis = []
    if not args.skip_analysis and combined_requests:
        try:
            requests.packages.urllib3.disable_warnings()  # type: ignore
        except Exception:
            pass

        hit_counts = count_endpoint_hits(combined_requests)
        all_domains = sorted(hit_counts.keys(), key=lambda d: hit_counts[d], reverse=True)

        selected_domains = choose_domains_for_analysis(all_domains, hit_counts)
        print(f"[+] Selected domain(s): {', '.join(selected_domains)}")

        delay_raw = input("Delay between requests (ms) [1000]: ").strip()
        delay_ms = int(delay_raw) if delay_raw.isdigit() and int(delay_raw) >= 0 else 1000

        max_repl_raw = input("Max replacement attempts on rate-limit [10]: ").strip()
        max_replacement_attempts = int(max_repl_raw) if max_repl_raw.isdigit() and int(max_repl_raw) >= 0 else 10

        print("[*] Analyzing session headers per domain (replay + hash diff)...")
        session_analysis = analyze_session_headers(
            combined_requests,
            timeout_sec=args.timeout,
            selected_domains=selected_domains,
            delay_ms=delay_ms,
            max_replacement_attempts=max_replacement_attempts,
        )

    session_data = {
        "user_login": user_login,
        "hash_id": short_hash_id(user_login, url),
        "url": url,
        "proxy": proxy,
        "user_agent": user_agent,
        "session_analysis": session_analysis,
        "requests": combined_requests,
        "storage_state": storage_state,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(session_data, f, indent=4, ensure_ascii=False)

    print(f"[+] Session saved to {output_path}")
    print(f"[+] Total hit endpoint: {len(combined_requests)}")
    print(f"[+] Domains analyzed: {len(session_analysis)}")


if __name__ == "__main__":
    main()
