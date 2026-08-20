#!/usr/bin/env python3
"""Section 4.9.1 -- Self-Consistency Findings.

Re-invokes Qwen2.5:3B at temperature=0.8 (the Ollama default) instead of
the production temperature=0, k=5 independent repetitions per sampled
endpoint, using the SAME prompt (llm_classifier.build_similarity_prompt())
and SAME (baseline_body, current_resp_data) pair as the production call.
An endpoint is "stable" if all k scores land on the same side of
SIMILARITY_VULNERABLE_THRESHOLD (>=90 vs <90), "unstable" otherwise.

Sample: N=40 endpoints (random, seed=42) drawn from the combined pool of
UNCERTAIN rows across Anonymous Access + Session Swapping that have a
resolvable baseline response body in candidate.json. Parameter Mutation is
excluded (its ambiguous-module oracle is a deterministic heuristic, not an
LLM -- self-consistency is not applicable to a deterministic function).

Usage: python3 tools/self_consistency_experiment.py <domain>
"""
import csv
import importlib.util
import os
import random
import sys
from typing import Dict, List

import requests

_HERE = os.path.dirname(__file__)
_llmclass_spec = importlib.util.spec_from_file_location("llm_classifier", os.path.join(_HERE, "llm_classifier.py"))
llmclass = importlib.util.module_from_spec(_llmclass_spec)
_llmclass_spec.loader.exec_module(llmclass)

_engine_spec = importlib.util.spec_from_file_location("knumal_att4ck", os.path.join(_HERE, "..", "knumal-att4ck.py"))
engine = importlib.util.module_from_spec(_engine_spec)
_engine_spec.loader.exec_module(engine)

MODEL = "qwen2.5:3b"
K_REPETITIONS = 5
SAMPLE_SIZE = 40
SEED = 42

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


def call_ollama_temp(model: str, prompt: str, temperature: float):
    for attempt in range(3):
        try:
            response = requests.post(
                f"{llmclass.OLLAMA_URL}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": temperature},
                },
                timeout=60,
            )
            response.raise_for_status()
            return response.json().get("response", "")
        except requests.RequestException:
            if attempt < 2:
                import time
                time.sleep(3)
    return None


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

    print(f"=== Section 4.9.1 Self-Consistency -- Domain: {domain} ===")
    print(f"Total UNCERTAIN rows with resolvable baseline body: {len(uncertain_pool)} "
          f"({sum(1 for s, _ in uncertain_pool if s == 'anonymous')} Anonymous + "
          f"{sum(1 for s, _ in uncertain_pool if s == 'session_swapping')} Session Swapping)")

    random.seed(SEED)
    sample = random.sample(uncertain_pool, min(SAMPLE_SIZE, len(uncertain_pool)))
    print(f"Sample size: N={len(sample)} (seed={SEED})\n")

    unstable_count = 0
    total_calls = 0
    parse_errors = 0
    results = []

    for i, (surface, row) in enumerate(sample, start=1):
        baseline_body = response_index.get(row.get("knumal_resp"), "")
        current_body = row.get("current_resp_data", "")
        prompt = llmclass.build_similarity_prompt(baseline_body, current_body)

        scores = []
        for k in range(K_REPETITIONS):
            raw = call_ollama_temp(MODEL, prompt, 0.8)
            total_calls += 1
            if raw is None:
                parse_errors += 1
                continue
            score, _ = llmclass.parse_similarity_and_confidence(raw)
            if score is None:
                parse_errors += 1
                continue
            scores.append(score)

        if not scores:
            print(f"  [{i}/{len(sample)}] {row['endpoint']} -- ALL CALLS FAILED, skipping")
            continue

        sides = set(s >= llmclass.SIMILARITY_VULNERABLE_THRESHOLD for s in scores)
        stable = len(sides) == 1
        if not stable:
            unstable_count += 1

        results.append({"surface": surface, "endpoint": row["endpoint"], "scores": scores, "stable": stable})
        status = "STABLE" if stable else "UNSTABLE"
        print(f"  [{i}/{len(sample)}] {row['endpoint']} ({surface}) -- scores={scores} -- {status}")

    n_evaluated = len(results)
    flip_rate = unstable_count / n_evaluated if n_evaluated else float("nan")

    print(f"\n=== Summary ===")
    print(f"Endpoints evaluated: {n_evaluated}/{len(sample)}")
    print(f"Total LLM calls: {total_calls} ({parse_errors} parse/request errors)")
    print(f"Unstable (flip across threshold=90): {unstable_count} ({flip_rate*100:.1f}%)")
    print(f"Stable: {n_evaluated - unstable_count} ({(1-flip_rate)*100:.1f}%)")

    print("\nUnstable case detail:")
    for r in results:
        if not r["stable"]:
            print(f"  {r['endpoint']} ({r['surface']}): {r['scores']}")


if __name__ == "__main__":
    main()
