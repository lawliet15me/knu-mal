#!/usr/bin/env python3
import glob
import json
import os
import readline
from typing import Any, Dict, List, Optional


# ==============================
# PATH COMPLETION (interactive input)
# ==============================

def _path_completer(text: str, state: int):

    if text.startswith("~"):
        text = os.path.expanduser(text)

    if os.path.isdir(text) and not text.endswith(os.sep):
        text += os.sep

    matches = glob.glob(text + "*")
    matches = [m + os.sep if os.path.isdir(m) else m for m in matches]

    try:
        return matches[state]
    except IndexError:
        return None


def prompt_path(message: str) -> str:

    readline.set_completer_delims(" \t\n;")

    if "libedit" in (readline.__doc__ or ""):
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")

    readline.set_completer(_path_completer)

    raw = input(message).strip()
    return os.path.expanduser(raw)


# ==============================
# SESSION LOADING
# ==============================

def load_session_files_by_tag(folder: str) -> Dict[str, Dict[str, Any]]:

    sessions_by_tag = {}

    for path in sorted(glob.glob(os.path.join(folder, "*.json"))):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        hash_id = data.get("hash_id", "")
        session_tag = hash_id.split("_")[-1] if hash_id else None

        if not session_tag:
            continue

        domains_with_session = [
            entry for entry in data.get("session_analysis", [])
            if entry.get("session")
        ]
        domains_with_session.sort(key=lambda e: e.get("hit_endpoint", 0), reverse=True)

        if not domains_with_session:
            continue

        sessions_by_tag[session_tag] = {
            "file": os.path.basename(path),
            "user_login": data.get("user_login"),
            "user_agent": data.get("user_agent"),
            "hash_id": hash_id,
            "session_tag": session_tag,
            "domains": domains_with_session,
        }

    return sessions_by_tag


# ==============================
# TRAFFIC LOADING
# ==============================

def load_traffic(json_path: str) -> List[Dict[str, Any]]:

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return data.get("traffic", [])


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


def unique_session_tags(traffic: List[Dict[str, Any]]) -> List[str]:

    tags = {t.get("session_tag") for t in traffic if t.get("session_tag")}
    return sorted(tags)


def describe_session(session_obj: Dict[str, Any]) -> str:

    if "authorization" in session_obj:
        return f"authorization header ({session_obj['authorization'][:40]}...)"

    if "cookie" in session_obj:
        return f"cookie ({session_obj['cookie'][:40]}...)"

    key = next(iter(session_obj), None)
    if key:
        return f"{key} ({str(session_obj[key])[:40]}...)"

    return "unknown"


# ==============================
# TERMINAL OUTPUT
# ==============================

def print_summary(sessions: List[Dict[str, Any]]):

    for sess in sessions:
        print("=" * 70)
        print(f"User Login   : {sess['user_login']}")
        print(f"User Agent   : {sess['user_agent']}")
        print(f"Session File : {sess['file']}")
        print("-" * 70)

        for domain_entry in sess["domains"]:
            domain = domain_entry.get("domain")
            hits = domain_entry.get("hit_endpoint", 0)
            session_desc = describe_session(domain_entry.get("session", {}))

            print(f"  Domain Target : {domain}")
            print(f"  Hit Endpoint  : {hits}")
            print(f"  Session       : {session_desc}")
            print()

    print("=" * 70)


# ==============================
# JSON OUTPUT (grouped by user)
# ==============================

def build_grouped_output(sessions: List[Dict[str, Any]], traffic: List[Dict[str, Any]]) -> Dict[str, Any]:

    candidates = []

    for sess in sessions:
        allowed_domains = {d["domain"] for d in sess["domains"]}
        session_tag = sess["session_tag"]

        matched_traffic = [
            t for t in traffic
            if t.get("session_tag") == session_tag and record_domain(t) in allowed_domains
        ]

        candidates.append({
            "user": {
                "user_login": sess["user_login"],
                "user_agent": sess["user_agent"],
                "hash_id": sess["hash_id"],
                "session_tag": session_tag,
                "domains": sess["domains"],
            },
            "traffic": matched_traffic,
        })

    return {"candidate": candidates}


# ==============================
# MAIN
# ==============================

def main():

    traffic_file = prompt_path("File traffic (hasil knumal-1, mis. malis-local.json): ")
    sessions_folder = prompt_path("Folder sessions: ")

    if not os.path.isfile(traffic_file):
        print(f"[!] File tidak ditemukan: {traffic_file}")
        return

    if not os.path.isdir(sessions_folder):
        print(f"[!] Folder tidak ditemukan: {sessions_folder}")
        return

    traffic = load_traffic(traffic_file)
    sessions_by_tag = load_session_files_by_tag(sessions_folder)

    matched_tags = [tag for tag in unique_session_tags(traffic) if tag in sessions_by_tag]

    if not matched_tags:
        print("[!] Tidak ada session_tag pada traffic yang cocok dengan file session manapun.")
        return

    sessions = [sessions_by_tag[tag] for tag in matched_tags]

    print_summary(sessions)

    grouped_output = build_grouped_output(sessions, traffic)

    output_path = f"{os.path.splitext(os.path.basename(traffic_file))[0]}_candidate.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(grouped_output, f, indent=4, ensure_ascii=False)

    candidates = grouped_output["candidate"]
    total_traffic = sum(len(c["traffic"]) for c in candidates)
    print(f"[+] Output tersimpan di {output_path}")
    print(f"[+] Total user: {len(candidates)}, total traffic matched: {total_traffic}")


if __name__ == "__main__":
    main()
