#!/usr/bin/env python3
import argparse
import base64
import csv
import hashlib
import os
import re
import xml.etree.ElementTree as ET
import json
from urllib.parse import urlparse, parse_qs
from typing import Dict, Optional, Any

from model_read_xml import RequestBodyParser


# ==============================
# CONFIG
# ==============================

KEYWORDS = ["username", "userid", "id", "uid", "user", "nik"]
DENY_RESPONSE_CONTENT_TYPE = []
DENY_HTTP_STATUS_CODE = ["304", "401", "403"]

SESSION_TAG_PATTERN = re.compile(r"_knu-mal_([a-zA-Z0-9]+)$")


def extract_session_tag(user_agent: str) -> Optional[str]:

    match = SESSION_TAG_PATTERN.search(user_agent or "")
    return match.group(1) if match else None


# ==============================
# HTTP REQUEST PARSER
# ==============================

def parse_http_request(raw_request: str):

    # Normalize CRLF
    raw_request = raw_request.replace("\r\n", "\n")

    lines = raw_request.split("\n")
    headers = {}
    body = ""
    is_body = False

    for line in lines[1:]:
        line = line.strip()

        if line == "":
            is_body = True
            continue

        if not is_body:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        else:
            body += line

    request_line = lines[0].strip() if lines else ""

    try:
        method, path, _ = request_line.split()
    except Exception:
        return headers, {}, {}, None, None, None

    parsed_url = urlparse(path)

    query_params = {
        k: [str(vv) for vv in v]
        for k, v in parse_qs(parsed_url.query, keep_blank_values=True).items()
    }

    body_params = RequestBodyParser.parse(headers, body)

    clean_path = parsed_url.path

    return headers, query_params, body_params, method, clean_path, path


# ==============================
# MULTI PARAM EXTRACTION (FLATTENED)
# ==============================

def extract_parameters_by_keywords(query_params: dict, body_params: dict) -> dict:
    found = {}

    combined = {}
    combined.update(query_params or {})
    combined.update(body_params or {})

    for key, values in combined.items():
        if not key:
            continue

        key_lower = key.lower()

        if any(keyword in key_lower for keyword in KEYWORDS):

            if isinstance(values, list) and values:
                # Flatten single-value list
                if len(values) == 1:
                    found[key] = values[0]
                else:
                    found[key] = values  # keep list if multi-value
            else:
                found[key] = values

    return found


# ==============================
# RESPONSE HEADER PARSER
# ==============================

def parse_response_headers(raw_response: str):

    raw_response = raw_response.replace("\r\n", "\n")
    headers = {}

    for line in raw_response.split("\n"):
        line = line.strip()
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
        if line == "":
            break

    return headers


def extract_response_body(raw_response: str) -> str:

    raw_response = raw_response.replace("\r\n", "\n")
    _, sep, body = raw_response.partition("\n\n")

    return body if sep else ""


def hash_response_body(body: str) -> str:

    return hashlib.sha256(body.strip().encode(errors="ignore")).hexdigest()


def sniff_content_type(body: str) -> str:
    """Fallback detection from the body itself, for when the Content-Type
    header is missing or misleading (common in VAPT where APIs mislabel
    their responses)."""

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

    return "other"


def detect_content_type(resp_headers: Dict[str, str], body: str) -> str:
    """Two-layer content-type detection: trust the Content-Type header first
    (json/xml/html by prefix), fall back to sniffing the body when the header
    is absent or doesn't match a known type."""

    header_value = resp_headers.get("Content-Type", "").lower()

    if "application/json" in header_value:
        return "json"

    if "text/xml" in header_value or "application/xml" in header_value:
        return "xml"

    if "text/html" in header_value:
        return "html"

    return sniff_content_type(body)


def build_request_fingerprint_source(endpoint: str, query_params: dict, body_params: dict) -> str:

    combined = {}
    combined.update(query_params or {})
    combined.update(body_params or {})

    params_str = "&".join(
        f"{key}={values[0] if isinstance(values, list) and values else values}"
        for key, values in sorted(combined.items())
    )

    return f"{endpoint}\n{params_str}"


def hash_request(endpoint: str, query_params: dict, body_params: dict) -> str:

    source = build_request_fingerprint_source(endpoint, query_params, body_params)
    return hashlib.sha256(source.strip().encode(errors="ignore")).hexdigest()


# ==============================
# PROCESS XML
# ==============================

def process_xml(file_path: str) -> Dict[str, Any]:

    tree = ET.parse(file_path)
    root = tree.getroot()

    traffic_output = []
    domain_counts: Dict[str, int] = {}
    status_counts: Dict[str, int] = {}
    status_path_counts: Dict[tuple, int] = {}

    for item in root.findall("item"):

        # ===== TIME =====
        time_value = item.findtext("time")

        status_code = item.findtext("status")
        if status_code in DENY_HTTP_STATUS_CODE:
            continue

        status_counts[status_code] = status_counts.get(status_code, 0) + 1

        host_elem = item.find("host")
        host_domain = (host_elem.text or "").strip() if host_elem is not None else None

        if host_domain:
            domain_counts[host_domain] = domain_counts.get(host_domain, 0) + 1

        port_val = item.findtext("port")
        protocol_val = item.findtext("protocol")

        # ===== REQUEST =====
        req_elem = item.find("request")
        raw_request = (req_elem.text or "") if req_elem is not None else ""

        if req_elem is not None and req_elem.attrib.get("base64") == "true":
            try:
                raw_request = base64.b64decode(raw_request).decode(errors="ignore")
            except Exception:
                raw_request = ""

        headers, query_params, body_params, method, clean_path, full_path = parse_http_request(raw_request)
        ua_raw = headers.get("User-Agent", "Unknown")

        endpoint = f"{method} {clean_path}" if method and clean_path else "UNKNOWN UNKNOWN"
        full_endpoint = f"{method} {full_path}" if method and full_path else "UNKNOWN UNKNOWN"

        status_path_counts[(status_code, full_endpoint)] = status_path_counts.get((status_code, full_endpoint), 0) + 1

        # ===== RESPONSE =====
        resp_elem = item.find("response")
        raw_response = (resp_elem.text or "") if resp_elem is not None else ""

        if resp_elem is not None and resp_elem.attrib.get("base64") == "true":
            try:
                raw_response = base64.b64decode(raw_response).decode(errors="ignore")
            except Exception:
                raw_response = ""

        resp_headers = parse_response_headers(raw_response)
        resp_content_type = resp_headers.get("Content-Type", "").lower()

        if any(deny in resp_content_type for deny in DENY_RESPONSE_CONTENT_TYPE):
            continue

        response_body = extract_response_body(raw_response)
        response_body_hash = hash_response_body(response_body)
        content_type = detect_content_type(resp_headers, response_body)
        request_hash = hash_request(endpoint, query_params, body_params)

        # ===== PARAMETER EXTRACTION =====
        detected_parameters = extract_parameters_by_keywords(query_params, body_params)

        traffic_output.append({
            "time": time_value,
            "host": host_domain,
            "port": port_val,
            "protocol": protocol_val,
            "http_status": status_code,
            "endpoint": endpoint,
            "parameters": detected_parameters,
            "request": raw_request,
            "response": raw_response,
            "content-type": content_type,
            "knumal_req": request_hash,
            "knumal_resp": response_body_hash,
            "user_agent": ua_raw,
            "session_tag": extract_session_tag(ua_raw)
        })

    sorted_domains = sorted(domain_counts.items(), key=lambda kv: kv[1], reverse=True)
    sorted_status = sorted(status_counts.items(), key=lambda kv: kv[1], reverse=True)
    sorted_status_path = sorted(status_path_counts.items(), key=lambda kv: kv[1], reverse=True)

    return {
        "summary": {
            "total_domains": len(sorted_domains),
            "domain_hits": [
                {"domain": domain, "count": count} for domain, count in sorted_domains
            ],
            "status_hits": [
                {"http_status": status, "count": count} for status, count in sorted_status
            ],
            "status_path_hits": [
                {"http_status": status, "path": path, "count": count}
                for (status, path), count in sorted_status_path
            ],
        },
        "traffic": traffic_output
    }


# ==============================
# CLI
# ==============================

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True)
    parser.add_argument("-o", "--output", default=None)
    parser.add_argument("--tsv-output", default="output_status_path.tsv")
    args = parser.parse_args()

    output_path = args.output or f"{os.path.splitext(os.path.basename(args.file))[0]}.json"

    result = process_xml(args.file)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4, ensure_ascii=False)

    with open(args.tsv_output, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(["http_status_code", "path"])
        for entry in result["summary"]["status_path_hits"]:
            writer.writerow([entry["http_status"], entry["path"]])

    print(f"[+] Done. Output saved to {output_path}")
    print(f"[+] TSV output saved to {args.tsv_output}")
    print(f"[+] Total traffic records: {len(result['traffic'])}")
    print()
    print("[+] HTTP status code summary:")
    for entry in result["summary"]["status_hits"]:
        print(f"    {entry['http_status']}: {entry['count']}")


if __name__ == "__main__":
    main()
