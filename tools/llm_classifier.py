#!/usr/bin/env python3
"""llm_classifier.py: LLM-assisted triage of UNCERTAIN anonymous-attack results.

Pipeline:
  1. Load baseline.json, keep records with classification == "ambiguous",
     collect their knumal_req + http_status (the AUTHENTICATED capture status).
  2. Load the anonymous_attack_result.tsv, keep rows with result == "UNCERTAIN"
     whose knumal_req matches one of the ambiguous baseline records above.
  3. Load candidate.json, look up http_status by knumal_req (same value as
     baseline.json's http_status for that knumal_req -- kept as a separate
     lookup because that's the source the spec names explicitly).
  4. For each matched row:
       - if baseline http_status != current_resp_code (the anonymous REPLAY's
         live status) -> rule-based decision, no LLM call needed:
         "not_vulnerable_by_rule_http_code" (the endpoint responded
         differently without a session -- e.g. 403 instead of 200 -- so it
         did reject the anonymous request at the HTTP level).
       - otherwise (status codes match, e.g. both 200), the HTTP status alone
         can't tell rejection from a real leak -- ask the LLM to read
         current_resp_data and decide whether it still contains real user
         data (PII) or looks like a rejection despite the 200:
         "vulnerable_by_llm" / "unaffected_by_llm".
  5. Write one result_llm_<model> column per model run, inserted right after
     "result", into a single combined output TSV.

Run sequentially through every model listed in MODELS (or --models on the
CLI) against the same Ollama server (default http://localhost:11434). Only
one model is ever loaded in memory at a time -- each model is explicitly
unloaded (keep_alive=0) before the next one starts, so this is safe to run
on memory-constrained machines."""
import argparse
import csv
import glob
import importlib.util
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import openpyxl
import requests

# knumal-att4ck.py sits one directory up from this file (tools/llm_classifier.py)
_ENGINE_PATH = os.path.join(os.path.dirname(__file__), "..", "knumal-att4ck.py")


def _load_module(path: str, name: str):

    spec = importlib.util.spec_from_file_location(name, os.path.abspath(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


engine = _load_module(_ENGINE_PATH, "knumal_att4ck")

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")

GROUND_TRUTH_FILENAME = "ground_truth.xlsx"
GROUND_TRUTH_SLUG_COL = 1       # column B (0-indexed): "Slug"
GROUND_TRUTH_ATTACK_PATTERN_COL = 14  # column O (0-indexed): "ATTACK PATTERN"
SLUG_PATTERN = re.compile(r"^(GET|POST|PUT|DELETE|PATCH)\s+/api/user/([^/]+)")

# Default model list: every model this project has pulled locally so far.
# Override with --models "model1,model2,..." to run a different subset.
MODELS = [
    "qwen2.5:0.5b",
    "qwen2.5:1.5b",
    "qwen2.5:3b",
    "qwen3.5:0.8B",
    "qwen3.5:2b",
    "llama3.2:3b",
    "gemma:2b",
]


def model_column_suffix(model: str) -> str:
    """Turn a model name into a TSV-column-safe suffix, e.g.
    "qwen2.5:1.5b" -> "qwen2_5_1_5b", "gemma:2b" -> "gemma_2b"."""

    return re.sub(r"[^a-zA-Z0-9]+", "_", model).strip("_").lower()

BASELINE_FILENAME = "api_malis_local_baseline.json"
TSV_FILENAME = "api_malis_local_anonymous_attack_result.tsv"
CANDIDATE_GLOB = "*.json"

REQUEST_TIMEOUT = 60
LLM_RETRY_DELAY_SECONDS = 3
MAX_LLM_ATTEMPTS = 3


# ==============================
# INPUT LOADING
# ==============================

def load_ambiguous_baseline(path: str) -> Dict[str, str]:
    """Returns knumal_req -> http_status for every baseline record whose
    classification == "ambiguous"."""

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    result: Dict[str, str] = {}
    for host_entry in data.get("cluster", []):
        for user_entry in host_entry.get("children", []):
            for record in user_entry.get("children", []):
                if record.get("classification") != "ambiguous":
                    continue
                knumal_req = record.get("knumal_req")
                if knumal_req:
                    result[knumal_req] = record.get("http_status", "")

    return result


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


def choose_candidate_file(files: List[str]) -> Optional[str]:

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


def load_candidate_http_status(path: str) -> Dict[str, str]:
    """Returns knumal_req -> http_status, scanning candidate.json traffic."""

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    result: Dict[str, str] = {}
    for cand in data.get("candidate", []):
        for record in cand.get("traffic", []):
            knumal_req = record.get("knumal_req")
            if knumal_req and knumal_req not in result:
                result[knumal_req] = record.get("http_status", "")

    return result


def load_tsv_rows(path: str) -> Tuple[List[str], List[Dict[str, str]]]:

    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        header = reader.fieldnames or []
        rows = list(reader)

    return header, rows


# ==============================
# LLM CLASSIFICATION
# ==============================

def build_similarity_prompt(baseline_body: str, current_body: str) -> str:
    """Ask the LLM to score how similar two response bodies are (0-100),
    AND how confident it is in that score (0-100), in a single call.

    The similarity question replaced two earlier approaches that both
    measurably failed:
      1. "Was the request rejected?" -- relied on the model recognizing
         rejection phrasing (e.g. "unauthorized", "forbidden"), and failed on
         responses that reject access with non-standard wording and a 200
         status (e.g. {"msg": "Request accepted, no data exposed"}).
      2. "Does this body contain PII (name/phone/DOB/address/email/employee
         ID)?" -- qwen2.5:3b was very sensitive to how many PII categories
         were listed in the prompt: a short list (name, email) scored
         correctly, but adding more categories (phone, address, DOB, etc)
         made the model MORE likely to answer NO even when the body
         obviously contained a real name, email, phone, or address.

    Comparing the two actual response bodies side by side sidesteps both
    failure modes: the model doesn't need to recognize rejection wording or
    recall a category list, it just judges whether current_body still looks
    like the same underlying data as baseline_body (the authenticated
    owner's real response) -- a rejection response (null/empty/generic
    fields) will naturally score low, and a body carrying the same person's
    data (regardless of which specific fields those are) will score high.

    The confidence question is asked in the SAME call, right after the
    similarity judgment, as the model's own self-assessment of that
    judgment -- deliberately not a separate call. An earlier attempt at a
    separate confidence-only call (with or without repeating the similarity
    number in the prompt) always came back identical to the similarity score
    regardless of how obvious the case was, which suggested the model needs
    the similarity judgment freshly in front of it to reason about
    confidence at all, rather than being asked to reconstruct it from a
    bare number in an unrelated follow-up prompt."""
    return (
        f"Baseline response (from the authenticated resource owner):\n{baseline_body}\n\n"
        f"Current response (from the replayed request being tested):\n{current_body}\n\n"
        "Step 1: On a scale of 0 to 100, how similar is the current response "
        "to the baseline response in terms of the actual DATA it contains "
        "(not just JSON structure/formatting)? 0 means completely different "
        "content or no real data (e.g. an empty/null/rejected response), 100 "
        "means the same underlying data.\n"
        "Step 2: How confident are you in that similarity judgment, on a "
        "scale of 0 to 100? 0 means highly uncertain, 100 means completely "
        "certain.\n\n"
        "Answer with exactly two lines, nothing else:\n"
        "SIMILARITY: <number>\n"
        "CONFIDENCE: <number>"
    )


def call_ollama(model: str, prompt: str) -> Optional[str]:
    """Returns the raw text response, or None if every attempt failed."""

    last_error: Optional[Exception] = None
    for attempt in range(MAX_LLM_ATTEMPTS):
        try:
            response = requests.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    # temperature=0 for deterministic, reproducible
                    # classifications -- this is a yes/no security decision,
                    # not creative text generation, so sampling randomness
                    # only adds noise (confirmed: the same prompt flipped
                    # between UNAUTHORIZED/VULNERABLE across runs at the
                    # default temperature).
                    "options": {"temperature": 0},
                },
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            return response.json().get("response", "")
        except requests.RequestException as exc:
            last_error = exc
            if attempt < MAX_LLM_ATTEMPTS - 1:
                time.sleep(LLM_RETRY_DELAY_SECONDS)

    # Every attempt failed -- this is a GENUINE connection/technical failure
    # (Ollama down, unreachable, timeout), distinct from a successful call
    # that happens to answer "no fields"/"nothing found". Printed here,
    # not left silent, so this failure mode is as visible to an operator
    # as the context-window-exceeded warning is (check_context_window()) --
    # without this, a caller falling back to a static keyword list (e.g.
    # discover_identity_fields_by_llm()'s IDENTITY_FIELD_KEYWORDS) would do
    # so with no on-screen indication anything was wrong.
    print(
        f"\n[!] OLLAMA CALL FAILED after {MAX_LLM_ATTEMPTS} attempt(s) ({model}): "
        f"{type(last_error).__name__}: {last_error}. Falling back to any "
        f"static/default behavior the caller defines for this condition."
    )
    return None


# Similarity score (0-100) at or above this is treated as VULNERABLE --
# current response's data is judged close enough to the authenticated
# owner's baseline to be the same underlying leak. Ground-truth testing on
# 40 labeled rows showed a clean gap between UNAFFECTED (score <=50) and
# VULNERABLE (score >=95), so 90 sits safely inside that gap.
SIMILARITY_VULNERABLE_THRESHOLD = 90


def parse_similarity_and_confidence(raw: str) -> Tuple[Optional[int], Optional[int]]:
    """Extracts the SIMILARITY and CONFIDENCE numbers from the two-line
    format build_similarity_prompt() asks for. Falls back to treating the
    first two integers found anywhere in the response as
    (similarity, confidence) if the SIMILARITY:/CONFIDENCE: labels aren't
    present verbatim -- models sometimes drop the labels despite being asked
    to keep them, and the two-numbers-in-order fallback is more robust than
    requiring an exact match."""

    similarity_match = re.search(r"SIMILARITY:\s*(\d{1,3})", raw, re.IGNORECASE)
    confidence_match = re.search(r"CONFIDENCE:\s*(\d{1,3})", raw, re.IGNORECASE)

    if similarity_match and confidence_match:
        similarity = int(similarity_match.group(1))
        confidence = int(confidence_match.group(1))
    else:
        numbers = re.findall(r"\d{1,3}", raw)
        similarity = int(numbers[0]) if len(numbers) >= 1 else None
        confidence = int(numbers[1]) if len(numbers) >= 2 else None

    similarity = similarity if similarity is not None and 0 <= similarity <= 100 else None
    confidence = confidence if confidence is not None and 0 <= confidence <= 100 else None

    return similarity, confidence


# Qwen2.5:3B's documented context window (Table 4.4/Section 4.4,
# Bab4_experiment_6_agt.txt). Section 4.13 of that document found the
# EFFECTIVE runtime limit on the project's scanner machine can be smaller
# than this (~16,386 tokens observed, most likely due to Ollama's
# memory-aware automatic context sizing) -- so this constant is used as a
# conservative, documented upper bound for PRE-FLIGHT flagging purposes,
# not a guarantee that every prompt under this size is safe on every
# machine.
QWEN_CONTEXT_WINDOW_TOKENS = 32768

# Empirical chars-per-token ratio calibrated against this project's own
# JSON-heavy response bodies via Ollama's own prompt_eval_count (see
# tools/context_window_experiment.py, Section 4.13.2: measured ratio was
# ~3.037 chars/token). Rounded down to 3.0 here so the estimate is
# conservative -- it OVER-estimates token count slightly, making a
# borderline prompt more likely to be flagged than missed.
CHARS_PER_TOKEN_ESTIMATE = 3.0

# Headroom reserved under the raw context window for the model's own reply
# tokens (SIMILARITY/CONFIDENCE lines are short, but this keeps the
# pre-flight check conservative rather than assuming zero output budget).
CONTEXT_WINDOW_OUTPUT_RESERVE_TOKENS = 512


def estimate_prompt_tokens(prompt: str) -> int:
    """Rough token-count estimate for a prompt string, calibrated to this
    project's JSON-heavy response bodies (see CHARS_PER_TOKEN_ESTIMATE's
    docstring). NOT a substitute for the model's own tokenizer -- used only
    to flag prompts likely to exceed the context window BEFORE they are
    sent, since Ollama itself gives no error when a prompt is silently
    truncated (Bab4_experiment_6_agt.txt Section 4.13.5)."""

    return int(len(prompt) / CHARS_PER_TOKEN_ESTIMATE)


def check_context_window(prompt: str, context_window_tokens: int = QWEN_CONTEXT_WINDOW_TOKENS) -> Tuple[bool, int]:
    """Returns (exceeded, estimated_tokens). exceeded is True when the
    prompt's ESTIMATED token count leaves no room under
    context_window_tokens once CONTEXT_WINDOW_OUTPUT_RESERVE_TOKENS is
    reserved for the model's reply. This is a best-effort PRE-FLIGHT check,
    not a guarantee -- it exists specifically to accommodate cases where an
    oversized endpoint slips past manual dataset-level exclusion (Section
    4.5's GET /api/menus exclusion was manual, not enforced by this
    pipeline -- see Section 4.14, Limitation 1)."""

    estimated = estimate_prompt_tokens(prompt)
    exceeded = estimated > (context_window_tokens - CONTEXT_WINDOW_OUTPUT_RESERVE_TOKENS)
    return exceeded, estimated


def classify_with_llm(model: str, baseline_body: str, response_body: str) -> Tuple[str, Optional[int], Optional[int], bool]:
    """Returns (result, similarity_score, confidence_score, context_window_exceeded)
    where result is "vulnerable_by_llm" / "unaffected_by_llm" / "llm_error",
    both scores are the raw 0-100 values from a SINGLE LLM call (None on
    parse failure), and context_window_exceeded is True when the
    constructed prompt was estimated (check_context_window()) to exceed
    Qwen2.5:3B's context window BEFORE the call was made.

    The LLM call is still made even when context_window_exceeded is True --
    this function does not skip or fall back on its own, it only reports
    the condition so the caller can flag it in a warning and/or a report
    column. Section 4.13 (Bab4_experiment_6_agt.txt) demonstrated that
    Ollama returns a normally-formatted, successfully-parseable response
    even when the prompt is silently truncated -- so an oversized prompt is
    otherwise indistinguishable from a legitimate low-similarity case
    without this pre-flight check.

    See build_similarity_prompt()'s docstring for why similarity compares
    the current response against the baseline instead of asking a
    category-based PII yes/no question (two earlier prompt designs both
    measurably failed), and for why confidence is asked in the same call
    rather than as a separate follow-up (an earlier separate-call design
    always echoed the similarity score instead of judging independently)."""

    prompt = build_similarity_prompt(baseline_body, response_body)
    context_exceeded, estimated_tokens = check_context_window(prompt)
    if context_exceeded:
        print(
            f"\n[!] CONTEXT WINDOW EXCEEDED: prompt ~{estimated_tokens:,} estimated tokens "
            f"> {QWEN_CONTEXT_WINDOW_TOKENS:,}-token limit ({model}). Proceeding with the "
            f"call, but the verdict below may be UNRELIABLE -- Ollama truncates silently "
            f"instead of erroring (see Bab4_experiment_6_agt.txt Section 4.13)."
        )

    raw = call_ollama(model, prompt)
    if raw is None:
        return "llm_error", None, None, context_exceeded

    score, confidence = parse_similarity_and_confidence(raw)
    if score is None:
        return "llm_error", None, confidence, context_exceeded

    result = "vulnerable_by_llm" if score >= SIMILARITY_VULNERABLE_THRESHOLD else "unaffected_by_llm"
    return result, score, confidence, context_exceeded


def unload_ollama_model(model: str) -> None:
    """Explicitly unload a model from Ollama's memory (keep_alive=0) so only
    one model is ever resident at a time -- Ollama otherwise keeps a model
    loaded for a few minutes after its last request by default, which lets
    consecutive model passes overlap in memory even though this script calls
    them strictly one after another."""

    try:
        requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": model, "keep_alive": 0},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        pass


# ==============================
# MAIN CLASSIFICATION FLOW
# ==============================

def classify_row(row: Dict[str, str], baseline_status: str, model: str,
                  response_index: Dict[str, str]) -> str:

    current_status = row.get("current_resp_code", "")

    if str(baseline_status) != str(current_status):
        return "not_vulnerable_by_rule_http_code"

    baseline_body = response_index.get(row.get("knumal_resp"), "")
    if not baseline_body:
        return "llm_error"

    result, _score, _confidence, _context_exceeded = classify_with_llm(model, baseline_body, row.get("current_resp_data", ""))
    return result


def render_progress_bar(completed: int, total: int, width: int = 30) -> None:

    fraction = completed / total if total else 1.0
    filled = int(width * fraction)
    bar = "#" * filled + "-" * (width - filled)
    end = "\n" if completed == total else ""
    print(f"\r    [{bar}] {completed}/{total}", end=end, flush=True)


def run_model_pass(model: str, rows: List[Dict[str, str]], eligible_indices: List[int],
                    ambiguous_status: Dict[str, str], response_index: Dict[str, str]) -> Tuple[Dict[int, str], float]:
    """Returns (row_index -> result_llm value, total_seconds) for every eligible row.
    total_seconds only covers this model's classification loop (load time and
    unload time are excluded, since those are one-off costs not part of the
    per-row inference speed being compared across models)."""

    print(f"\n[+] Running model: {model}")
    results: Dict[int, str] = {}

    start = time.monotonic()
    for i, row_idx in enumerate(eligible_indices, start=1):
        row = rows[row_idx]
        baseline_status = ambiguous_status[row["knumal_req"]]
        results[row_idx] = classify_row(row, baseline_status, model, response_index)
        render_progress_bar(i, len(eligible_indices))
    elapsed = time.monotonic() - start

    unload_ollama_model(model)
    print(f"[+] Unloaded {model} from Ollama memory")
    print(f"[+] {model} took {elapsed:.1f}s for {len(eligible_indices)} rows ({elapsed/len(eligible_indices):.2f}s/row)")

    return results, elapsed


# ==============================
# GROUND-TRUTH EVALUATION
# ==============================
#
# Ground truth positive (vulnerable to the ANONYMOUS attack specifically) is
# any row whose ATTACK PATTERN column contains "Anonymous" -- rows labelled
# "Session Swapping attack" only, or "SAFE", are negative for this attack.
# Matched to a TSV row via the endpoint's slug: "/api/user/{slug}/..." ->
# ground truth's "Slug" column.

def load_ground_truth(path: str) -> Dict[str, str]:
    """Returns slug -> ATTACK PATTERN string."""

    wb = openpyxl.load_workbook(path, data_only=True)
    ws = wb.active

    ground_truth: Dict[str, str] = {}
    for row in ws.iter_rows(min_row=2, values_only=True):
        slug = row[GROUND_TRUTH_SLUG_COL]
        pattern = row[GROUND_TRUTH_ATTACK_PATTERN_COL]
        if slug:
            ground_truth[slug] = pattern

    return ground_truth


def extract_slug(endpoint: str) -> Optional[str]:

    match = SLUG_PATTERN.match(endpoint or "")
    return match.group(2) if match else None


def evaluate_against_ground_truth(rows: List[Dict[str, str]], eligible_indices: List[int],
                                   result_col: str, ground_truth: Dict[str, str]) -> Dict[str, Any]:
    """Returns TP/FP/TN/FN/unmatched counts plus precision/recall/specificity
    for one model's result column, against ground_truth's ATTACK PATTERN.

    "positive" prediction = a result value starting with "vulnerable"
    (vulnerable_by_rule_http_code / vulnerable_by_llm)."""

    tp = fp = tn = fn = unmatched = 0

    for row_idx in eligible_indices:
        row = rows[row_idx]
        slug = extract_slug(row.get("endpoint", ""))
        pattern = ground_truth.get(slug) if slug else None

        if pattern is None:
            unmatched += 1
            continue

        is_gt_positive = "Anonymous" in pattern
        is_pred_positive = row.get(result_col, "").startswith("vulnerable")

        if is_gt_positive and is_pred_positive:
            tp += 1
        elif not is_gt_positive and is_pred_positive:
            fp += 1
        elif not is_gt_positive and not is_pred_positive:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    specificity = tn / (tn + fp) if (tn + fp) else None

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "unmatched": unmatched,
        "precision": precision, "recall": recall, "specificity": specificity,
    }


def print_ranking(model_stats: List[Dict[str, Any]]) -> None:
    """model_stats: list of {"model": str, "elapsed": float, **evaluate_against_ground_truth() output}.
    Ranked by accuracy first (recall, since this dataset's ground truth is
    all-positive so precision/recall/accuracy collapse to the same thing when
    FP=0 -- recall is the more meaningful of the two whenever the class
    balance skews positive), then by speed (elapsed time ascending) as the
    tiebreaker among equally-accurate models."""

    def accuracy_key(stats: Dict[str, Any]) -> float:
        total = stats["tp"] + stats["fp"] + stats["tn"] + stats["fn"]
        correct = stats["tp"] + stats["tn"]
        return correct / total if total else 0.0

    ranked = sorted(model_stats, key=lambda s: (-accuracy_key(s), s["elapsed"]))

    print("\nModel Ranking (accuracy first, then speed)")
    print("=" * 100)
    print(f"{'Rank':<5}{'Model':<20}{'Accuracy':<10}{'Precision':<11}{'Recall':<9}{'Specificity':<13}{'Time (s)':<10}{'s/row':<8}")
    print("-" * 100)
    for rank, stats in enumerate(ranked, start=1):
        acc = accuracy_key(stats)
        total_rows = stats["tp"] + stats["fp"] + stats["tn"] + stats["fn"]
        precision = f"{stats['precision']:.3f}" if stats["precision"] is not None else "-"
        recall = f"{stats['recall']:.3f}" if stats["recall"] is not None else "-"
        specificity = f"{stats['specificity']:.3f}" if stats["specificity"] is not None else "-"
        s_per_row = stats["elapsed"] / total_rows if total_rows else 0.0
        print(f"{rank:<5}{stats['model']:<20}{acc:<10.3f}{precision:<11}{recall:<9}{specificity:<13}{stats['elapsed']:<10.1f}{s_per_row:<8.2f}")
    print("=" * 100)


# ==============================
# CLI
# ==============================

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", default=BASELINE_FILENAME)
    parser.add_argument("--tsv", default=TSV_FILENAME)
    parser.add_argument("--output", default=None)
    parser.add_argument("--models", default=None,
                         help="Comma-separated Ollama model names to run sequentially. "
                              "Defaults to every model in MODELS.")
    args = parser.parse_args()

    models = [m.strip() for m in args.models.split(",")] if args.models else MODELS

    if not os.path.isfile(args.baseline):
        print(f"[!] Baseline file not found: {args.baseline}")
        sys.exit(1)

    if not os.path.isfile(args.tsv):
        print(f"[!] TSV file not found: {args.tsv}")
        sys.exit(1)

    print(f"[+] Loading ambiguous baseline records from {args.baseline}")
    ambiguous_status = load_ambiguous_baseline(args.baseline)
    print(f"[+] Ambiguous baseline records: {len(ambiguous_status)}")

    candidate_files = find_candidate_files(".")
    selected_candidate_file = choose_candidate_file(candidate_files)
    if selected_candidate_file:
        candidate_status = load_candidate_http_status(selected_candidate_file)
        response_index = engine.build_response_index_by_knumal_resp(selected_candidate_file)
        print(f"[+] Using {selected_candidate_file} for candidate http_status lookup and baseline response bodies.")
    else:
        print("[!] No candidate.json found -- candidate http_status lookup and similarity scoring will be empty.")
        candidate_status = {}
        response_index = {}

    print(f"[+] Loading {args.tsv}")
    header, rows = load_tsv_rows(args.tsv)
    print(f"[+] Total rows: {len(rows)}")

    eligible_indices = [
        i for i, row in enumerate(rows)
        if row.get("result") == "UNCERTAIN" and row.get("knumal_req") in ambiguous_status
    ]
    print(f"[+] Rows eligible for LLM triage (UNCERTAIN + ambiguous baseline match): {len(eligible_indices)}")

    if not eligible_indices:
        print("[!] Nothing to process, exiting.")
        return

    # Prefer candidate.json's http_status when available (per spec); fall
    # back to baseline.json's http_status for the same knumal_req otherwise
    # (they're the same authenticated-capture value in practice).
    effective_status: Dict[str, str] = {}
    for row_idx in eligible_indices:
        knumal_req = rows[row_idx]["knumal_req"]
        effective_status[knumal_req] = candidate_status.get(knumal_req, ambiguous_status[knumal_req])

    all_model_results: Dict[str, Dict[int, str]] = {}
    model_elapsed: Dict[str, float] = {}
    for model in models:
        results, elapsed = run_model_pass(model, rows, eligible_indices, effective_status, response_index)
        all_model_results[model] = results
        model_elapsed[model] = elapsed

    result_idx = header.index("result")
    result_columns = {m: f"result_llm_{model_column_suffix(m)}" for m in models}
    new_columns = [result_columns[m] for m in models]
    new_header = header[:result_idx + 1] + new_columns + header[result_idx + 1:]

    # Write the LLM result values back into `rows` too, so
    # evaluate_against_ground_truth() can read them by column name the same
    # way it reads any other TSV column.
    for model in models:
        col = result_columns[model]
        for row_idx, value in all_model_results[model].items():
            rows[row_idx][col] = value

    output_path = args.output or f"{os.path.splitext(os.path.basename(args.tsv))[0]}_llm.tsv"
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(new_header)

        for i, row in enumerate(rows):
            values = [row.get(col, "") for col in header]
            llm_values = [
                all_model_results[model].get(i, "") for model in models
            ]
            new_row = values[:result_idx + 1] + llm_values + values[result_idx + 1:]
            writer.writerow(new_row)

    print(f"\n[+] Output saved to {output_path}")

    if os.path.isfile(GROUND_TRUTH_FILENAME):
        print(f"\n[+] Evaluating against {GROUND_TRUTH_FILENAME}")
        ground_truth = load_ground_truth(GROUND_TRUTH_FILENAME)

        model_stats = []
        for model in models:
            stats = evaluate_against_ground_truth(rows, eligible_indices, result_columns[model], ground_truth)
            stats["model"] = model
            stats["elapsed"] = model_elapsed[model]
            model_stats.append(stats)

        print_ranking(model_stats)
    else:
        print(f"\n[!] {GROUND_TRUTH_FILENAME} not found -- skipping ranking, timing still logged above per model.")


if __name__ == "__main__":
    main()
