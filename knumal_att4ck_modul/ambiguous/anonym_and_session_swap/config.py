MENU_NAME = "anonym_and_session_swap"

# This module does NOT replay HTTP requests -- it post-processes a TSV that
# simple/anonymous OR simple/session_swapping already produced (see
# anonym_and_session_swap_llm.py's module docstring for why both are handled
# by the same file). It defines run_standalone(baseline_path, tsv_path)
# instead of build_attack_plan/evaluate; knumal-att4ck.py's main() detects
# that (via hasattr) and branches into a simpler flow (pick baseline.json + a
# result TSV, no domain/thread/delay prompts) instead of the normal replay
# pipeline.
# ENABLE = True so it's selectable directly from the model/attack menu.
ENABLE = True
ATTACK_SCRIPT = "anonym_and_session_swap_llm.py"
EXTRA_INPUTS = []

# TRIGGERS: which simple/<attack_name> runs should automatically offer this
# module as a follow-up once their output TSV has UNCERTAIN rows. Unlike the
# normal 1:1 "ambiguous/<attack_name> mirrors simple/<attack_name>" naming
# convention, this folder's name doesn't match either trigger -- so
# knumal-att4ck.py's offer_ambiguous_triage() looks at TRIGGERS instead of
# assuming a name match.
TRIGGERS = ["anonymous", "session_swapping"]
