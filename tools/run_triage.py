#!/usr/bin/env python3
"""Standalone runner for the ambiguous/anonym_and_session_swap LLM triage
module, driven with explicit args instead of the interactive CLI menu, so it
can run non-interactively (piped stdin still answers the candidate.json
prompt inside load_response_index() when more than one exists)."""
import importlib.util
import sys

MODULE_PATH = "knumal_att4ck_modul/ambiguous/anonym_and_session_swap/anonym_and_session_swap_llm.py"


def main():
    baseline_path = sys.argv[1]
    tsv_path = sys.argv[2]

    spec = importlib.util.spec_from_file_location("anonym_and_session_swap_llm", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    module.run_standalone(baseline_path, tsv_path)


if __name__ == "__main__":
    main()
