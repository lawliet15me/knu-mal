MENU_NAME = "parameter_mutation_fuzzing"
ENABLE = True
ATTACK_SCRIPT = "parameter_mutation_fuzzing_attack.py"

# Unlike ambiguous/anonym_and_session_swap, this module DOES replay HTTP
# requests itself (build_attack_plan/evaluate/filter_records, same contract
# as simple/parameter_mutation_fuzzing) -- it is not a TSV post-processor.
# That's because simple/parameter_mutation_fuzzing never sends a request for
# classification=="ambiguous" endpoints at all (see that module's docstring),
# so there is no existing response to post-process here; this module has to
# generate and send its own mutated requests, then run a two-stage oracle
# (structural pre-check + LLM-based categorical identity judgment) instead
# of the Jaccard structural comparison alone used by the "simple" counterpart
# (ambiguous endpoints carry volatile fields -- tokens/timestamps -- that
# break both hash and pure structural comparison).
#
# Stage 2 uses Qwen2.5:3B (via Ollama) with a categorical prompt (pick one of
# four concrete scenarios) rather than the free-form 0-100 similarity prompt
# used elsewhere in the framework -- see
# parameter_mutation_fuzzing_attack.py's "TWO-STAGE ORACLE" comment block for
# the full rationale, and parameter_mutation_fuzzing_attack.py.old for the
# prior deterministic field-diff heuristic this replaced.
#
# fuzz_range: how far above/below each numeric parameter's baseline value to
# fuzz (default 1 -- e.g. baseline=5 tries 4 and 6, negatives/zero are always
# floored out). Free-text so the user can override per run.
#
# sweep_direction: which side(s) of the baseline value the +/-fuzz_range
# sweep actually tries. "both" (default) keeps the original two-sided sweep
# (base-fuzz_range..base+fuzz_range) available for other runs. "up" tries
# base+1..base+fuzz_range only (e.g. fuzz_range=1 -> only base+1); "down"
# tries base-fuzz_range..base-1 only. The reference-mutation strategy
# (get_reference_values(), real values seen on other users' baselines) is
# unaffected by this setting either way.
EXTRA_INPUTS = [
    {
        "name": "fuzz_range",
        "prompt": "Fuzz range around each numeric parameter's baseline value (default 1 -> tries base-1..base+1, floored at 1)",
    },
    {
        "name": "sweep_direction",
        "prompt": "Sweep direction: both / up / down (default both -> base-fuzz_range..base+fuzz_range)",
    },
]

# RESULT_LABELS: overrides the wording shown for each result bucket in the
# terminal summary (knumal-att4ck.py's print_summary). Optional -- any key
# left out falls back to the engine's generic default.
RESULT_LABELS = {
    "VULNERABLE": "another user's object reachable via parameter mutation (LLM identity judgment)",
    "UNAFFECTED": "parameter mutation rejected or returned own data unchanged (LLM identity judgment)",
    "UNCERTAIN": "no baseline response body found, or LLM call/parse failed",
}
