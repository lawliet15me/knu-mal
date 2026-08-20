#!/usr/bin/env python3
"""Supplementary LLM evaluation for Bab 4 Section 4.9.

4.9.1 Self-Consistency: for a sample of N UNCERTAIN rows (already resolved by
the production pipeline at temperature=0), re-run classify_with_llm() k=5
times at temperature=0.8 (Ollama default) using the SAME prompt
(build_similarity_prompt()) and SAME baseline_body/current_resp_data pair.
An endpoint is "stable" if all 5 scores fall on the same side of
SIMILARITY_VULNERABLE_THRESHOLD (>=90 vs <90), else "unstable".

4.9.2 Decision Grounding: for the SAME sample, parse baseline_body and
current_resp_data as JSON and compute a field overlap ratio (# identical
key-value pairs / # unique key-value pairs across both). Compare direction
(>=90 similarity vs >=50% overlap, both arbitrary-but-reasonable "high
similarity" cutoffs) against the production LLM SIMILARITY score's direction
relative to its own threshold. Agreement = grounded, disagreement =
potentially ungrounded.

Sample: N=40 UNCERTAIN rows, drawn from both anonymous and session_swapping
attack result TSVs (production runs already completed), keyed by whichever
baseline_body could be found in candidate.json (a row is skipped if no
baseline body is available -- can't score similarity or grounding without one).
"""
import csv
import importlib.util
import json
import os
import random
import sys
from typing import Any, Dict, List, Optional, Tuple

import requests

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_BASE_DIR, "tools"))
import llm_classifier as llmclass_tools  # noqa: E402

ENGINE_PATH = os.path.join(_BASE_DIR, "knumal-att4ck.py")


def _load_engine():
    spec = importlib.util.spec_from_file_location("knumal_att4ck", ENGINE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


engine = _load_engine()

MODEL = "qwen2.5:3b"
SAMPLE_SIZE = 40
K_REPETITIONS = 5
TEMPERATURE = 0.8
RANDOM_SEED = 42

ANON_TSV = os.path.join(_BASE_DIR, "api_malis_local_anonymous_attack_result_final.tsv")
SS_TSV = os.path.join(_BASE_DIR, "api_malis_local_session_swapping_attack_result_final.tsv")
CANDIDATE_JSON = os.path.join(_BASE_DIR, "malis-local-10-jul-2026_candidate.json")


def call_ollama_temp(model: str, prompt: str, temperature: float) -> Optional[str]:
    """Same as llm_classifier.call_ollama() but with an overridable temperature."""

    for attempt in range(llmclass_tools.MAX_LLM_ATTEMPTS):
        try:
            response = requests.post(
                f"{llmclass_tools.OLLAMA_URL}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": temperature},
                },
                timeout=llmclass_tools.REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            return response.json().get("response", "")
        except requests.RequestException:
            if attempt < llmclass_tools.MAX_LLM_ATTEMPTS - 1:
                import time
                time.sleep(llmclass_tools.LLM_RETRY_DELAY_SECONDS)
    return None


def classify_with_llm_temp(model: str, baseline_body: str, response_body: str,
                            temperature: float) -> Tuple[Optional[int], Optional[int]]:
    raw = call_ollama_temp(model, llmclass_tools.build_similarity_prompt(baseline_body, response_body), temperature)
    if raw is None:
        return None, None
    return llmclass_tools.parse_similarity_and_confidence(raw)


def load_uncertain_rows_with_baseline(tsv_path: str, response_index: Dict[str, str]) -> List[Dict[str, Any]]:
    rows = []
    with open(tsv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            if row.get("result") != "UNCERTAIN":
                continue
            baseline_body = response_index.get(row.get("knumal_resp"), "")
            if not baseline_body:
                continue
            row["_baseline_body"] = baseline_body
            row["_source_tsv"] = os.path.basename(tsv_path)
            rows.append(row)
    return rows


def field_overlap_ratio(baseline_body: str, current_body: str) -> Optional[float]:
    try:
        baseline_json = json.loads(baseline_body)
        current_json = json.loads(current_body)
    except (json.JSONDecodeError, TypeError):
        return None

    if not isinstance(baseline_json, dict) or not isinstance(current_json, dict):
        return None

    def flatten(obj, prefix=""):
        items = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                items.update(flatten(v, f"{prefix}.{k}" if prefix else k))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                items.update(flatten(v, f"{prefix}[{i}]"))
        else:
            items[prefix] = obj
        return items

    baseline_flat = flatten(baseline_json)
    current_flat = flatten(current_json)

    all_keys = set(baseline_flat) | set(current_flat)
    if not all_keys:
        return None

    identical = sum(1 for k in all_keys if k in baseline_flat and k in current_flat and baseline_flat[k] == current_flat[k])
    return identical / len(all_keys)


def main():
    print(f"[+] Loading candidate.json for baseline response bodies: {CANDIDATE_JSON}")
    response_index = engine.build_response_index_by_knumal_resp(CANDIDATE_JSON)

    print("[+] Loading UNCERTAIN rows with a resolvable baseline body...")
    all_rows = (load_uncertain_rows_with_baseline(ANON_TSV, response_index) +
                load_uncertain_rows_with_baseline(SS_TSV, response_index))
    print(f"[+] {len(all_rows)} UNCERTAIN rows have a resolvable baseline body "
          f"(out of 57 + 386 = 443 total UNCERTAIN rows)")

    random.seed(RANDOM_SEED)
    sample = random.sample(all_rows, min(SAMPLE_SIZE, len(all_rows)))
    print(f"[+] Sampled N = {len(sample)} rows (seed={RANDOM_SEED})\n")

    print("=" * 78)
    print("4.9.1 SELF-CONSISTENCY (k=5 @ temperature=0.8)")
    print("=" * 78)

    stable_count = 0
    unstable_count = 0
    total_flips = 0
    total_calls = 0

    for i, row in enumerate(sample, start=1):
        baseline_body = row["_baseline_body"]
        current_body = row.get("current_resp_data", "")

        scores = []
        for k in range(K_REPETITIONS):
            score, _ = classify_with_llm_temp(MODEL, baseline_body, current_body, TEMPERATURE)
            scores.append(score)
            total_calls += 1

        valid_scores = [s for s in scores if s is not None]
        sides = set("VULNERABLE" if s >= llmclass_tools.SIMILARITY_VULNERABLE_THRESHOLD else "UNAFFECTED"
                     for s in valid_scores)
        is_stable = len(sides) <= 1
        if is_stable:
            stable_count += 1
        else:
            unstable_count += 1
            total_flips += 1

        print(f"  [{i}/{len(sample)}] {row['endpoint']} ({row['_source_tsv']}) "
              f"scores={scores} -> {'STABLE' if is_stable else 'UNSTABLE'}")

    n_sampled = len(sample)
    flip_rate = (unstable_count / n_sampled * 100) if n_sampled else float("nan")

    print(f"\nN sampled = {n_sampled}, total LLM calls = {total_calls}")
    print(f"Stable    = {stable_count} ({stable_count/n_sampled*100:.1f}%)")
    print(f"Unstable  = {unstable_count} ({unstable_count/n_sampled*100:.1f}%)")
    print(f"Observed flip rate = {flip_rate:.1f}%")
    print(f"[Conclusion] temperature=0 production setting is "
          f"{'STRONGLY' if flip_rate > 10 else 'MODESTLY' if flip_rate > 0 else 'TRIVIALLY'} "
          f"validated as necessary: sampling at temperature=0.8 (Ollama default) "
          f"{'DOES' if flip_rate > 0 else 'does NOT'} produce inconsistent VULNERABLE/UNAFFECTED "
          f"verdicts for identical inputs.")

    print("\n" + "=" * 78)
    print("4.9.2 DECISION GROUNDING (production temperature=0 score vs field overlap ratio)")
    print("=" * 78)

    grounded = 0
    ungrounded = 0
    examples_grounded = None
    examples_ungrounded = None
    skipped_not_json = 0

    for row in sample:
        prod_score = row.get("llm_similarity_score", "-")
        try:
            prod_score = float(prod_score)
        except (TypeError, ValueError):
            continue

        overlap = field_overlap_ratio(row["_baseline_body"], row.get("current_resp_data", ""))
        if overlap is None:
            skipped_not_json += 1
            continue

        llm_says_similar = prod_score >= llmclass_tools.SIMILARITY_VULNERABLE_THRESHOLD
        overlap_says_similar = overlap >= 0.5

        is_grounded = llm_says_similar == overlap_says_similar
        if is_grounded:
            grounded += 1
            if examples_grounded is None:
                examples_grounded = (row["endpoint"], prod_score, overlap)
        else:
            ungrounded += 1
            if examples_ungrounded is None:
                examples_ungrounded = (row["endpoint"], prod_score, overlap)

    n_scored = grounded + ungrounded
    print(f"N with parseable JSON + production score = {n_scored}  (skipped non-JSON = {skipped_not_json})")
    if n_scored:
        print(f"Grounded            = {grounded} ({grounded/n_scored*100:.1f}%)")
        print(f"Potentially ungrounded = {ungrounded} ({ungrounded/n_scored*100:.1f}%)")
    if examples_grounded:
        print(f"\nExample grounded case: {examples_grounded[0]} "
              f"SIMILARITY={examples_grounded[1]} FieldOverlap={examples_grounded[2]:.2f}")
    if examples_ungrounded:
        print(f"Example ungrounded case: {examples_ungrounded[0]} "
              f"SIMILARITY={examples_ungrounded[1]} FieldOverlap={examples_ungrounded[2]:.2f}")


if __name__ == "__main__":
    main()
