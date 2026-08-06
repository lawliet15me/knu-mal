#!/usr/bin/env python3
"""ambiguous/anonym_and_session_swap: LLM-assisted triage of UNCERTAIN rows
from a completed simple/anonymous OR simple/session_swapping attack run.

Both attacks produce UNCERTAIN rows via the exact same rule (hash differs but
the replay's http_status matches the baseline's authenticated http_status),
and both need the exact same follow-up question answered: does the current
response still carry the SAME underlying data as the authenticated owner's
baseline response? There is no per-context wording -- both contexts are
handled identically, which is why a single shared module still makes sense.

This is NOT a replay-based attack module and does NOT go through
knumal-att4ck.py's build_attack_plan/evaluate/run_attacks contract -- it
never sends a request to the target at all. It only reads a TSV that
simple/anonymous or simple/session_swapping already produced (plus a
candidate.json for baseline response bodies -- see llmclass_tools.classify_with_llm()),
re-checks each UNCERTAIN row using qwen2.5:3b, and writes back two columns
at the end: "llm_similarity_score", "final_result" (copying every other
column through unchanged, including session_swapping's extra "source_user"
column when present). Column names use underscores, not spaces, like every
other column in these TSVs -- a header containing a space has been observed
to make some Excel versions misdetect the file's delimiter on import.

Which context produced the TSV (anonymous vs session_swapping) is still
auto-detected from the input TSV's columns for informational purposes (a
"source_user" column means session_swapping), even though the classification
logic itself no longer depends on it.

Called two ways:
  1. Automatically by knumal-att4ck.py's main(), right after a
     simple/anonymous or simple/session_swapping run finishes writing its
     output TSV, if that TSV has any UNCERTAIN rows (see this folder's
     config.py TRIGGERS list).
  2. Directly from the model/attack menu (ambiguous -> anonym_and_session_swap)
     or standalone from the CLI:
         python3 anonym_and_session_swap_llm.py <baseline.json> <attack_result.tsv>

Classification logic:
  - baseline http_status (from baseline.json, classification == "ambiguous")
    != current_resp_code (the replay's live status) -> UNAFFECTED, no LLM
    call needed (the endpoint DID reject the request at the HTTP level).
  - status codes match (usually both 200) -> look up the baseline response
    BODY (from candidate.json, keyed by knumal_resp) and ask the LLM, in a
    single call, for a similarity score (0-100): how close is
    current_resp_data to the baseline in terms of actual data content? (see
    llmclass_tools.build_similarity_prompt()'s docstring for why this replaced two
    earlier, less reliable prompt designs). Then:
      - similarity >= 90 (llmclass_tools.SIMILARITY_VULNERABLE_THRESHOLD) -> VULNERABLE
      - similarity < 90 -> UNAFFECTED
      - no baseline body found for this row's knumal_resp -> LLM_ERROR (can't
        compare against nothing; check that the right candidate.json was
        selected)

Rows that were NOT "UNCERTAIN" in the input TSV are copied through with
final_result = their original result (VULNERABLE or UNAFFECTED, decided
earlier by simple/anonymous or simple/session_swapping's hash/http_status
rule) and llm_similarity_score = "-", since those rows never went through
the LLM at all -- nothing from the input is dropped. Ctrl+C during the LLM
loop is caught: whatever rows were already classified get written out as a
partial result, instead of losing everything."""
import csv
import importlib.util
import os
import sys
from typing import Dict, List, Optional, Tuple

# tools/llm_classifier.py and knumal-att4ck.py sit three directories up from this file
_BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..")
_LLMCLASS_PATH = os.path.join(_BASE_DIR, "tools", "llm_classifier.py")
_ENGINE_PATH = os.path.join(_BASE_DIR, "knumal-att4ck.py")


def _load_module(path: str, name: str):

    spec = importlib.util.spec_from_file_location(name, os.path.abspath(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


llmclass_tools = _load_module(_LLMCLASS_PATH, "llm_classifier")
engine = _load_module(_ENGINE_PATH, "knumal_att4ck")

MODEL = "qwen2.5:3b"


def detect_context(header: List[str]) -> str:
    """"source_user" is session_swapping_attack.py's own EXTRA column (see
    get_extra_columns() there) -- no other attack module uses that column
    name, so its presence unambiguously identifies a session_swapping TSV.
    Anything else is assumed to be anonymous's output. Kept purely for
    logging/informational purposes -- classify_uncertain_row() no longer
    branches on it."""

    return "session_swapping" if "source_user" in header else "anonymous"


def load_response_index() -> Dict[str, str]:
    """Finds and loads a candidate.json for baseline response bodies (same
    file format/lookup knumal-att4ck.py's main() uses for response_similarity).
    Auto-picks the only file if there's just one; prompts if there's more
    than one (never silently guesses "newest" -- see
    knumal-att4ck.py's choose_candidate_file() docstring for why that's
    unsafe once more than one candidate.json exists in the project folder)."""

    candidate_files = engine.find_candidate_files(".")
    selected = engine.choose_candidate_file(candidate_files)
    if not selected:
        print("[!] No candidate.json found -- similarity scoring will fail for all UNCERTAIN rows.")
        return {}

    print(f"[+] Using {selected} for baseline response bodies.")
    return engine.build_response_index_by_knumal_resp(selected)


def classify_uncertain_row(row: Dict[str, str], baseline_status: str,
                            response_index: Dict[str, str], context: str = "") -> Tuple[str, Optional[int], Optional[int]]:
    """http_status-first, then-LLM logic, mapped to this module's result
    vocabulary: UNAFFECTED / VULNERABLE / LLM_ERROR, plus the raw similarity
    score (None when not applicable; the LLM's confidence score is still
    returned as the 3rd tuple element for callers that want it, but this
    module no longer uses it -- see llmclass_tools.classify_with_llm()'s docstring).
    `context` is accepted for backward-compatible call signatures but is no
    longer used.

    The similarity score alone decides VULNERABLE vs UNAFFECTED --
    llmclass_tools.SIMILARITY_VULNERABLE_THRESHOLD (90). Ground-truth testing on 40
    labeled rows showed a clean gap (UNAFFECTED similarity always <=50,
    VULNERABLE similarity always >=95), so 90 sits safely inside that gap."""

    current_status = row.get("current_resp_code", "")

    if str(baseline_status) != str(current_status):
        return "UNAFFECTED", None, None

    baseline_body = response_index.get(row.get("knumal_resp"), "")
    if not baseline_body:
        return "LLM_ERROR", None, None

    llm_result, score, confidence = llmclass_tools.classify_with_llm(MODEL, baseline_body, row.get("current_resp_data", ""))

    if llm_result == "llm_error":
        return "LLM_ERROR", score, confidence

    if llm_result == "unaffected_by_llm":
        return "UNAFFECTED", score, confidence
    if llm_result == "vulnerable_by_llm":
        return "VULNERABLE", score, confidence

    return "LLM_ERROR", score, confidence


def run_standalone(baseline_path: str, tsv_path: str, output_path: Optional[str] = None) -> str:

    print(f"[+] Loading ambiguous baseline records from {baseline_path}")
    baseline_status = llmclass_tools.load_ambiguous_baseline(baseline_path)
    print(f"[+] Ambiguous baseline records: {len(baseline_status)}")

    response_index = load_response_index()

    print(f"[+] Loading {tsv_path}")
    header, rows = llmclass_tools.load_tsv_rows(tsv_path)
    print(f"[+] Total rows: {len(rows)}")

    context = detect_context(header)
    print(f"[+] Detected context: {context}")

    uncertain_indices = [i for i, row in enumerate(rows) if row.get("result") == "UNCERTAIN"]
    print(f"[+] UNCERTAIN rows to triage with {MODEL}: {len(uncertain_indices)}")

    final_results: Dict[int, str] = {
        i: row.get("result", "") for i, row in enumerate(rows) if row.get("result") != "UNCERTAIN"
    }
    similarity_scores: Dict[int, str] = {}

    cancelled = False
    if uncertain_indices:
        try:
            for progress, row_idx in enumerate(uncertain_indices, start=1):
                row = rows[row_idx]
                status = baseline_status.get(row.get("knumal_req"), "")
                result, score, _ = classify_uncertain_row(row, status, response_index, context)
                final_results[row_idx] = result
                similarity_scores[row_idx] = "-" if score is None else str(score)
                llmclass_tools.render_progress_bar(progress, len(uncertain_indices))
        except KeyboardInterrupt:
            cancelled = True
            print("\n[!] Cancelled -- writing partial results for rows processed so far.")
        finally:
            llmclass_tools.unload_ollama_model(MODEL)

    output_path = output_path or f"{os.path.splitext(os.path.basename(tsv_path))[0]}_final.tsv"
    new_header = header + ["llm_similarity_score", "final_result"]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(new_header)
        for i, row in enumerate(rows):
            values = [row.get(col, "") for col in header]
            values.append(similarity_scores.get(i, "-"))
            values.append(final_results.get(i, ""))
            writer.writerow(values)

    status_word = "Partial" if cancelled else "Final"
    print(f"\n[+] {status_word} output saved to {output_path}")
    return output_path


def main():

    if len(sys.argv) != 3:
        print("Usage: anonym_and_session_swap_llm.py <baseline.json> <attack_result.tsv>")
        sys.exit(1)

    run_standalone(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
