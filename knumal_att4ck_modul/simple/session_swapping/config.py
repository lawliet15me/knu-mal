MENU_NAME = "session_swapping"
ENABLE = True
ATTACK_SCRIPT = "session_swapping_attack.py"

# source_user: username whose session (session_detected) will be swapped into
# every OTHER user's requests on the same host, to test whether their session
# alone is enough to reach other users' resources (BAC via session swapping).
# "type": "user_select" makes the engine render a numbered menu of every
# distinct user_login found in the selected baseline/domain(s), instead of a
# free-text prompt.
EXTRA_INPUTS = [
    {
        "name": "source_user",
        "prompt": "Select source user (this user's session will be reused on other users' requests)",
        "type": "user_select",
    },
]

# RESULT_LABELS: overrides the wording shown for each result bucket in the
# terminal summary (knumal-att4ck.py's print_summary). Optional -- any key
# left out falls back to the engine's generic default.
RESULT_LABELS = {
    "VULNERABLE": "accessible using another user's session",
    "UNAFFECTED": "session not accepted for this resource",
    "UNCERTAIN": "hash differs, http_status matches baseline",
}
