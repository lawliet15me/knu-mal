MENU_NAME = "anonymous"
ENABLE = True
ATTACK_SCRIPT = "anonymous_attack.py"

# EXTRA_INPUTS: extra prompts asked to the user before the attack runs, then
# passed as a dict to build_attack_plan(record, extra_inputs) and
# evaluate(plan, attack_result, response_index, extra_inputs).
# Example:
# EXTRA_INPUTS = [
#     {"name": "test_input", "prompt": "Test input"},
# ]
EXTRA_INPUTS = []

# RESULT_LABELS: overrides the wording shown for each result bucket in the
# terminal summary (knumal-att4ck.py's print_summary). Optional -- any key
# left out falls back to the engine's generic default.
RESULT_LABELS = {
    "VULNERABLE": "accessible without auth",
    "UNAFFECTED": "auth still required",
    "UNCERTAIN": "hash differs, http_status matches baseline",
}
