#!/usr/bin/env python3
"""Section 4.9.2 -- Decision Grounding Findings.

For the SAME N=40 sample used in Section 4.9.1 (self_consistency_experiment.py,
same seed=42 sampling over the same UNCERTAIN pool), parses baseline_body
and current_resp_data as JSON, flattens each to a dotted-path -> value map,
and computes a field overlap ratio = |shared identical key-value pairs| /
|total unique key-value pairs across both|. An endpoint is "grounded" if the
production LLM SIMILARITY score (temperature=0, single call -- the actual
production classify_with_llm() call, not the 4.9.1 temperature=0.8 samples)
and the field overlap ratio agree in direction relative to their respective
thresholds (>=90 similarity vs >=0.50 overlap ratio); "potentially
ungrounded" if they diverge. Endpoints whose body isn't valid JSON are
excluded from the ratio (kept in the un-parseable count).

Usage: python3 tools/decision_grounding_experiment.py <domain>
"""
import csv
import importlib.util
import json
import os
import random
import sys
from typing import Any, Dict, List, Set, Tuple

_HERE = os.path.dirname(__file__)
_llmclass_spec = importlib.util.spec_from_file_location("llm_classifier", os.path.join(_HERE, "llm_classifier.py"))
llmclass = importlib.util.module_from_spec(_llmclass_spec)
_llmclass_spec.loader.exec_module(llmclass)

_engine_spec = importlib.util.spec_from_file_location("knumal_att4ck", os.path.join(_HERE, "..", "knumal-att4ck.py"))
engine = importlib.util.module_from_spec(_engine_spec)
_engine_spec.loader.exec_module(engine)

SAMPLE_SIZE = 40
SEED = 42
FIELD_OVERLAP_THRESHOLD = 0.50

DOMAINS = {
    "nunu": {
        "anonymous_tsv": "nunu_all_anonymous_attack_result_final.tsv",
        "session_swap_tsv": "nunu_all_session_swapping_attack_result_final.tsv",
        "candidate_json": "nunu-local_candidate.json",
        "full_access_user": "test4",
    },
    "malis": {
        "anonymous_tsv": "malis_all_anonymous_attack_result_final.tsv",
        "session_swap_tsv": "malis_all_session_swapping_attack_result_final.tsv",
        "candidate_json": "malis-local_candidate.json",
        "full_access_user": "test9",
    },
}


def load_tsv(path: str) -> List[dict]:
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter="\t")
        return list(reader)


def flatten(obj: Any, path: str = "") -> Set[Tuple[str, str]]:
    pairs = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            child = f"{path}.{k}" if path else k
            pairs |= flatten(v, child)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            pairs |= flatten(v, f"{path}[{i}]")
    else:
        pairs.add((path, json.dumps(obj, sort_keys=True)))
    return pairs


def field_overlap_ratio(baseline_body: str, current_body: str):
    try:
        baseline_obj = json.loads(baseline_body)
        current_obj = json.loads(current_body)
    except (json.JSONDecodeError, TypeError):
        return None

    baseline_pairs = flatten(baseline_obj)
    current_pairs = flatten(current_obj)

    total_unique = baseline_pairs | current_pairs
    if not total_unique:
        return None
    shared = baseline_pairs & current_pairs
    return len(shared) / len(total_unique)


def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else "nunu"
    cfg = DOMAINS[domain]
    full_user = cfg["full_access_user"]

    response_index = engine.build_response_index_by_knumal_resp(cfg["candidate_json"])

    anon_rows = [r for r in load_tsv(cfg["anonymous_tsv"]) if r.get("login_info") == full_user]
    ss_rows = [r for r in load_tsv(cfg["session_swap_tsv"]) if r.get("login_info") == full_user]

    uncertain_pool = []
    for r in anon_rows:
        if r.get("result") == "UNCERTAIN" and response_index.get(r.get("knumal_resp")):
            uncertain_pool.append(("anonymous", r))
    for r in ss_rows:
        if r.get("result") == "UNCERTAIN" and response_index.get(r.get("knumal_resp")):
            uncertain_pool.append(("session_swapping", r))

    print(f"=== Section 4.9.2 Decision Grounding -- Domain: {domain} ===")
    print(f"Total UNCERTAIN rows with resolvable baseline body: {len(uncertain_pool)}")

    random.seed(SEED)
    sample = random.sample(uncertain_pool, min(SAMPLE_SIZE, len(uncertain_pool)))
    print(f"Sample size: N={len(sample)} (seed={SEED}, same sample as Section 4.9.1)\n")

    grounded = 0
    ungrounded = 0
    unparseable = 0
    detail = []

    for surface, row in sample:
        baseline_body = response_index.get(row.get("knumal_resp"), "")
        current_body = row.get("current_resp_data", "")

        ratio = field_overlap_ratio(baseline_body, current_body)
        if ratio is None:
            unparseable += 1
            continue

        llm_score_raw = row.get("llm_similarity_score")
        try:
            llm_score = float(llm_score_raw)
        except (TypeError, ValueError):
            unparseable += 1
            continue

        llm_side = llm_score >= llmclass.SIMILARITY_VULNERABLE_THRESHOLD
        overlap_side = ratio >= FIELD_OVERLAP_THRESHOLD
        is_grounded = llm_side == overlap_side

        if is_grounded:
            grounded += 1
        else:
            ungrounded += 1

        detail.append({
            "surface": surface, "endpoint": row["endpoint"],
            "llm_score": llm_score, "overlap_ratio": ratio, "grounded": is_grounded,
        })

    n_evaluated = grounded + ungrounded
    print(f"Sampled N={len(sample)}, unparseable/excluded={unparseable}, evaluated N={n_evaluated}")
    print(f"Grounded: {grounded} ({grounded/n_evaluated*100:.1f}%)" if n_evaluated else "Grounded: n/a")
    print(f"Potentially ungrounded: {ungrounded} ({ungrounded/n_evaluated*100:.1f}%)" if n_evaluated else "")

    print("\nDetail:")
    for d in detail:
        status = "Grounded" if d["grounded"] else "POTENTIALLY UNGROUNDED"
        print(f"  {d['endpoint']} ({d['surface']}) -- SIMILARITY={d['llm_score']:.1f} "
              f"FieldOverlap={d['overlap_ratio']:.2f} -- {status}")


if __name__ == "__main__":
    main()
