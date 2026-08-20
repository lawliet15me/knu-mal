#!/usr/bin/env python3
"""Section 4.13 -- Context Window Boundary Experiment.

Section 4.4 (Table 4.4) documents that GET /api/menus, the largest response
body actually observed in the 900-endpoint dataset (~232,000 characters,
~58,000 tokens), exceeds Qwen2.5:3B's 32,768-token context window -- and
that this endpoint was excluded from the evaluated ground truth (Section
4.5) rather than routed through the semantic path. Because of that
exclusion, none of the 2,700 production LLM calls reported in Chapter 4
(Sections 4.7-4.10) ever actually submitted an over-budget prompt to
Qwen2.5:3B -- but that claim was previously supported only by the exclusion
criterion itself, not by direct measurement of what the pipeline does when
the boundary IS crossed.

This script closes that gap empirically. It synthesizes a session-swapping
ambiguous case shaped like GET /api/menus in size (a bulk, paginated JSON
body) but WITH an embedded per-request identity block at the tail -- the
same "bulk array first, identity metadata last" shape as a realistic
oversized transaction/record-listing endpoint -- so the experiment can
distinguish "the model still classifies correctly despite the size" from
"the model classifies incorrectly because the identity signal fell outside
whatever context window Ollama actually used for the call."

It runs the EXACT production call used by the session-swapping ambiguous
module (llm_classifier.classify_with_llm(), the same function
anonym_and_session_swap_llm.classify_uncertain_row() calls), first exactly
as the production pipeline invokes it today (no num_ctx override -- see
llm_classifier.call_ollama()), then again with num_ctx explicitly set to
32,768 (the documented context window) and to 65,536 (double), to see
whether the boundary is actually enforced, whether Ollama truncates
silently, and whether that truncation flips a genuinely VULNERABLE
ground-truth case to UNAFFECTED.

Ground truth for the synthetic case: VULNERABLE (current_body is an exact
copy of baseline_body -- i.e. test10's session-swapped replay returns
test9's complete, oversized record unchanged, a textbook broken-access-
control leak).

Usage: python3 tools/context_window_experiment.py
"""
import importlib.util
import json
import os
import random
import time
from typing import Any, Dict, Optional

import requests

_HERE = os.path.dirname(__file__)
_llmclass_spec = importlib.util.spec_from_file_location("llm_classifier", os.path.join(_HERE, "llm_classifier.py"))
llmclass = importlib.util.module_from_spec(_llmclass_spec)
_llmclass_spec.loader.exec_module(llmclass)

MODEL = "qwen2.5:3b"
TARGET_CHARS = 232_000          # matches Table 4.4's observed GET /api/menus size
OWNER_USER_ID = "test9"
OWNER_NAME = "Fendi Tahir Daeng Lewa"
SWAPPED_USER_ID = "test10"
SEED = 42

CATEGORIES = ["Makanan Utama", "Minuman", "Camilan", "Dessert", "Paket Hemat"]


def build_oversized_body(owner_user_id: str, owner_name: str) -> str:
    """Builds a synthetic bulk-listing response shaped like GET /api/menus:
    a large paginated array of menu/transaction records first, followed by
    a small per-request identity block at the tail (account_holder,
    user_id) -- the field a session-swapping oracle actually needs to see
    to judge VULNERABLE vs UNAFFECTED. Placing it last, after ~232,000
    characters of bulk content, is deliberate: it is the piece most likely
    to be pushed outside the context window if silent front-truncation (or
    a small runtime num_ctx) is in effect."""

    rng = random.Random(SEED)
    records = []
    idx = 0
    running_len = 2  # account for the enclosing "[]"
    while running_len < TARGET_CHARS - 400:  # leave room for the identity tail
        record = {
            "menu_id": idx,
            "menu_name": f"Menu Item {idx:05d}",
            "category": rng.choice(CATEGORIES),
            "price": rng.randint(8_000, 85_000),
            "description": (
                "Deskripsi standar untuk item menu pada katalog staging "
                f"PT XYZ, entri ke-{idx}, digunakan semata-mata untuk "
                "membentuk payload berukuran besar yang setara dengan "
                "respons GET /api/menus pada Tabel 4.4."
            ),
            "available": bool(idx % 3),
            "image_url": f"https://cdn.malis.local/menu/{idx:05d}.jpg",
        }
        records.append(record)
        running_len += len(json.dumps(record, ensure_ascii=False)) + 1
        idx += 1

    payload = {
        "status": "success",
        "data": records,
        "requested_by": {
            "user_id": owner_user_id,
            "account_holder": owner_name,
            "role": "employee",
        },
    }
    return json.dumps(payload, ensure_ascii=False)


def call_ollama_with_options(model: str, prompt: str, options: Dict[str, Any]) -> Dict[str, Any]:
    """Same endpoint/shape as llm_classifier.call_ollama(), but returns the
    FULL response JSON (not just .response) so prompt_eval_count -- the
    number of prompt tokens Ollama actually fed to the model -- can be
    inspected directly. This field is the ground-truth signal for whether
    silent truncation occurred: if it is smaller than the prompt's true
    token count, part of the prompt (potentially including the tail
    identity block) never reached the model."""

    start = time.monotonic()
    response = requests.post(
        f"{llmclass.OLLAMA_URL}/api/generate",
        json={
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0, **options},
        },
        timeout=180,
    )
    elapsed = time.monotonic() - start
    response.raise_for_status()
    body = response.json()
    body["_elapsed_seconds"] = elapsed
    return body


def run_case(label: str, prompt: str, options: Dict[str, Any]) -> Dict[str, Any]:
    print(f"\n[+] Case: {label} (options={options})")
    try:
        raw = call_ollama_with_options(MODEL, prompt, options)
    except requests.RequestException as exc:
        print(f"    -> Ollama REQUEST FAILED: {exc}")
        return {"label": label, "options": options, "error": str(exc)}

    text = raw.get("response", "")
    similarity, confidence = llmclass.parse_similarity_and_confidence(text)
    prompt_eval_count = raw.get("prompt_eval_count")
    verdict = (
        "VULNERABLE" if similarity is not None and similarity >= llmclass.SIMILARITY_VULNERABLE_THRESHOLD
        else "UNAFFECTED" if similarity is not None
        else "LLM_ERROR (unparsable response)"
    )
    print(f"    prompt_eval_count (tokens actually fed to model): {prompt_eval_count}")
    print(f"    raw model output: {text.strip()!r}")
    print(f"    parsed similarity={similarity} confidence={confidence} -> verdict={verdict}")
    print(f"    elapsed: {raw['_elapsed_seconds']:.1f}s")

    return {
        "label": label,
        "options": options,
        "prompt_eval_count": prompt_eval_count,
        "eval_count": raw.get("eval_count"),
        "raw_response": text.strip(),
        "similarity": similarity,
        "confidence": confidence,
        "verdict": verdict,
        "elapsed_seconds": raw["_elapsed_seconds"],
    }


def estimate_tokens_via_ollama(sample_text: str) -> Optional[float]:
    """Calibrates a chars-per-token ratio for THIS corpus using a short,
    well-under-context probe (so prompt_eval_count for the probe is
    guaranteed untruncated), then uses that ratio to estimate the true
    (untruncated) token count of the full prompt for comparison against the
    oversized calls' actual prompt_eval_count."""

    probe = sample_text[:4000]
    raw = call_ollama_with_options(MODEL, probe, {"num_predict": 1})
    count = raw.get("prompt_eval_count")
    if not count:
        return None
    return len(probe) / count  # chars per token


def main():
    print("[+] Building synthetic oversized session-swapping case "
          f"(target ~{TARGET_CHARS:,} chars, matching Table 4.4's GET /api/menus)")
    baseline_body = build_oversized_body(OWNER_USER_ID, OWNER_NAME)
    # Ground truth: VULNERABLE. current_body is an exact copy of
    # baseline_body -- test10's session-swapped replay against test9's
    # resource returns test9's complete record unchanged.
    current_body = baseline_body

    print(f"[+] baseline_body length: {len(baseline_body):,} characters")
    print(f"[+] current_body length:  {len(current_body):,} characters")

    prompt = llmclass.build_similarity_prompt(baseline_body, current_body)
    print(f"[+] Full combined prompt length: {len(prompt):,} characters")

    chars_per_token = estimate_tokens_via_ollama(prompt)
    if chars_per_token:
        estimated_true_tokens = len(prompt) / chars_per_token
        print(f"[+] Calibrated ratio: {chars_per_token:.3f} chars/token "
              f"-> estimated TRUE prompt size: ~{estimated_true_tokens:,.0f} tokens")
    else:
        print("[!] Could not calibrate chars/token ratio (probe call failed)")

    results = []

    # Case A: production behaviour exactly as shipped today -- no num_ctx
    # override in llm_classifier.call_ollama(), so Ollama's own runtime
    # default applies.
    results.append(run_case("A: production call (no num_ctx override)", prompt, {}))

    # Case B: num_ctx explicitly set to the documented 32,768-token boundary.
    results.append(run_case("B: num_ctx=32768 (documented boundary)", prompt, {"num_ctx": 32768}))

    # Case C: num_ctx explicitly set to comfortably exceed the full prompt.
    results.append(run_case("C: num_ctx=65536 (double the boundary)", prompt, {"num_ctx": 65536}))

    print("\n" + "=" * 100)
    print("SUMMARY (ground truth = VULNERABLE for all three cases)")
    print("=" * 100)
    print(f"{'Case':<45}{'prompt_eval_count':<20}{'Similarity':<12}{'Verdict':<12}{'Correct?':<10}")
    for r in results:
        if "error" in r:
            print(f"{r['label']:<45}{'N/A (request failed)':<20}")
            continue
        correct = "YES" if r["verdict"] == "VULNERABLE" else "NO"
        print(f"{r['label']:<45}{str(r['prompt_eval_count']):<20}{str(r['similarity']):<12}{r['verdict']:<12}{correct:<10}")
    print("=" * 100)

    output_path = os.path.join(_HERE, "..", "context_window_experiment_result.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({
            "target_chars": TARGET_CHARS,
            "baseline_len": len(baseline_body),
            "current_len": len(current_body),
            "prompt_len": len(prompt),
            "chars_per_token_calibration": chars_per_token,
            "results": results,
        }, f, indent=2)
    print(f"\n[+] Full results written to {output_path}")


if __name__ == "__main__":
    main()
