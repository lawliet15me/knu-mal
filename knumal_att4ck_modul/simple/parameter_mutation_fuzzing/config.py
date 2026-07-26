MENU_NAME = "parameter_mutation_fuzzing"
ENABLE = True
ATTACK_SCRIPT = "parameter_mutation_fuzzing_attack.py"

# fuzz_range: how far above/below each numeric parameter's baseline value to
# fuzz (default 1 -- e.g. baseline=5 tries 4 and 6, negatives/zero are always
# floored out). Free-text so the user can override per run.
EXTRA_INPUTS = [
    {
        "name": "fuzz_range",
        "prompt": "Fuzz range around each numeric parameter's baseline value (default 1 -> tries base-1..base+1, floored at 1)",
    },
]

# RESULT_LABELS: overrides the wording shown for each result bucket in the
# terminal summary (knumal-att4ck.py's print_summary). Optional -- any key
# left out falls back to the engine's generic default.
RESULT_LABELS = {
    "VULNERABLE": "another user's object reachable via parameter mutation",
    "UNAFFECTED": "parameter mutation rejected or returned own data unchanged",
    "UNCERTAIN": "classification=ambiguous, out of scope for rule-based fuzzing (no request sent)",
}
