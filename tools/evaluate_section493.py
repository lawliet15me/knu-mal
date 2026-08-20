#!/usr/bin/env python3
"""Section 4.9.3 -- Rule-only vs. Full-Pipeline confusion matrix comparison,
for Anonymous Access and Session Swapping (the two surfaces whose semantic
path genuinely uses the LLM). Parameter Mutation's equivalent comparison is
already 4.5.3a (rule-only/simple) vs 4.5.3c (full pipeline) from
tools/evaluate_experiment.py.

Rule-only: endpoints resolved as UNCERTAIN by the deterministic path are
EXCLUDED from evaluation (not scored at all).
Full-pipeline: UNCERTAIN endpoints are resolved via final_result (LLM
triage) before scoring.

Usage: python3 tools/evaluate_section493.py <domain>
"""
import csv
import re
import sys
from typing import Dict, List, Tuple

import openpyxl

DOMAINS = {
    "nunu": {
        "ground_truth": "nunu_statistics_attack_map.xlsx",
        "anonymous_tsv": "nunu_all_anonymous_attack_result_final.tsv",
        "session_swap_tsv": "nunu_all_session_swapping_attack_result_final.tsv",
        "full_access_user": "test4",
    },
    "malis": {
        "ground_truth": "malis-statistics_attack_map.xlsx",
        "anonymous_tsv": "malis_all_anonymous_attack_result_final.tsv",
        "session_swap_tsv": "malis_all_session_swapping_attack_result_final.tsv",
        "full_access_user": "test9",
    },
}


def normalize_endpoint(ep: str) -> str:
    ep = ep.strip().split("?")[0]
    ep = re.sub(r"/\{[^}]+\}$", "", ep)
    ep = re.sub(r"/\d+$", "", ep)
    return ep


def load_ground_truth(path: str) -> Dict[str, dict]:
    wb = openpyxl.load_workbook(path, data_only=True)
    ws = wb["Attack Map"]
    rows = list(ws.iter_rows(min_row=1, values_only=True))
    header = rows[0]
    idx = {name: i for i, name in enumerate(header)}
    gt = {}
    for r in rows[1:]:
        ep = normalize_endpoint(r[idx["endpoint"]])
        gt[ep] = {"status": r[idx["status"]]}
    return gt


def load_tsv(path: str) -> List[dict]:
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter="\t")
        return list(reader)


def confusion(rows: List[Tuple[bool, str]]) -> Dict[str, int]:
    tp = fp = fn = tn = 0
    for gt_vuln, pred in rows:
        pred_vuln = pred == "VULNERABLE"
        if gt_vuln and pred_vuln:
            tp += 1
        elif not gt_vuln and pred_vuln:
            fp += 1
        elif gt_vuln and not pred_vuln:
            fn += 1
        else:
            tn += 1
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn}


def metrics(cm: Dict[str, int]) -> Dict[str, float]:
    tp, fp, fn, tn = cm["TP"], cm["FP"], cm["FN"], cm["TN"]
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    specificity = tn / (tn + fp) if (tn + fp) else float("nan")
    accuracy = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) else float("nan")
    return {"precision": precision, "recall": recall, "specificity": specificity, "accuracy": accuracy}


def eval_condition(rows_all, gt, surface, full_access_user, use_final: bool):
    rows_t1 = [r for r in rows_all if r.get("login_info") == full_access_user]

    scored = []
    excluded_uncertain = 0
    unmatched = 0
    for row in rows_t1:
        ep = normalize_endpoint(row["endpoint"])
        if ep not in gt:
            unmatched += 1
            continue

        status = gt[ep]["status"]
        gt_vuln = (status == "Anon") if surface == "anonymous" else (status in ("IDOR", "Anon"))

        rule_result = row["result"]
        if not use_final and rule_result == "UNCERTAIN":
            excluded_uncertain += 1
            continue

        pred = row["final_result"] if use_final else rule_result
        pred_vuln = str(pred).startswith("VULNERABLE")
        scored.append((gt_vuln, "VULNERABLE" if pred_vuln else "UNAFFECTED"))

    return scored, excluded_uncertain, unmatched, len(rows_t1)


def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else "nunu"
    cfg = DOMAINS[domain]

    gt = load_ground_truth(cfg["ground_truth"])
    anon_rows = load_tsv(cfg["anonymous_tsv"])
    ss_rows = load_tsv(cfg["session_swap_tsv"])
    full_user = cfg["full_access_user"]

    print(f"=== Section 4.9.3 -- Domain: {domain} ===\n")

    print("Table 4.7-style: Rule-only vs full-pipeline evaluation coverage")
    print(f"{'Surface':<20} {'Path':<28} {'TSVRows':>8} {'Evaluated':>10} {'Excluded':>30}")

    results = {}
    for surface_name, surface_key, rows in (
        ("Anonymous Access", "anonymous", anon_rows),
        ("Session Swapping", "session_swapping", ss_rows),
    ):
        rule_scored, excl_unc, unmatched, n_total = eval_condition(rows, gt, surface_key, full_user, use_final=False)
        full_scored, _, unmatched_full, _ = eval_condition(rows, gt, surface_key, full_user, use_final=True)

        print(f"{surface_name:<20} {'Rule-only (UNCERTAIN excl.)':<28} {n_total:>8} {len(rule_scored):>10} "
              f"{f'{excl_unc} UNCERTAIN + {unmatched} unmatched':>30}")
        print(f"{surface_name:<20} {'Full pipeline (final_result)':<28} {n_total:>8} {len(full_scored):>10} "
              f"{f'{unmatched_full} unmatched':>30}")

        results[surface_key] = {
            "rule": (confusion(rule_scored), len(rule_scored)),
            "full": (confusion(full_scored), len(full_scored)),
        }

    print("\nTable 4.8-style: Rule-only vs full-pipeline confusion matrix")
    print(f"{'Surface':<20} {'Path':<15} {'TP':>5} {'FP':>5} {'FN':>5} {'TN':>5}")
    for surface_name, surface_key in (("Anonymous Access", "anonymous"), ("Session Swapping", "session_swapping")):
        for path_name in ("rule", "full"):
            cm, _ = results[surface_key][path_name]
            label = "Rule-only" if path_name == "rule" else "Full pipeline"
            print(f"{surface_name:<20} {label:<15} {cm['TP']:>5} {cm['FP']:>5} {cm['FN']:>5} {cm['TN']:>5}")

    print("\nTable 4.9-style: Rule-only vs full-pipeline derived metrics")
    print(f"{'Surface':<20} {'Path':<15} {'Precision':>10} {'Recall':>8} {'Specificity':>12} {'Accuracy':>9}")
    for surface_name, surface_key in (("Anonymous Access", "anonymous"), ("Session Swapping", "session_swapping")):
        for path_name in ("rule", "full"):
            cm, _ = results[surface_key][path_name]
            m = metrics(cm)
            label = "Rule-only" if path_name == "rule" else "Full pipeline"
            print(f"{surface_name:<20} {label:<15} {m['precision']:>10.3f} {m['recall']:>8.3f} "
                  f"{m['specificity']:>12.3f} {m['accuracy']:>9.3f}")

    print("\nCoverage gain (full pipeline vs rule-only):")
    for surface_name, surface_key in (("Anonymous Access", "anonymous"), ("Session Swapping", "session_swapping")):
        _, n_rule = results[surface_key]["rule"]
        _, n_full = results[surface_key]["full"]
        gain = n_full - n_rule
        pct = gain / 900 * 100
        cm_rule, _ = results[surface_key]["rule"]
        cm_full, _ = results[surface_key]["full"]
        m_rule = metrics(cm_rule)
        m_full = metrics(cm_full)
        recall_delta = m_full["recall"] - m_rule["recall"]
        print(f"  {surface_name}: +{gain} endpoints (+{pct:.1f} pct pts coverage), "
              f"recall delta = {recall_delta:+.3f}")


if __name__ == "__main__":
    main()
