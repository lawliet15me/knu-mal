#!/usr/bin/env python3
"""Section 4.6 -- Static (Deterministic) vs Dynamic (Semantic/LLM) path
performance, per surface, for a given domain (nunu/malis).

For Anonymous Access and Session Swapping: "Static" rows are those whose
pre-LLM rule-based `result` column is already VULNERABLE or UNAFFECTED
(never touched the LLM); "Dynamic" rows are those where `result`==UNCERTAIN
and were resolved by LLM triage into `final_result`.

For Parameter Mutation, "Static" == the simple/Jaccard module standalone
(4.5.3a) and "Dynamic" == the ambiguous/identity-field-diff module
standalone (4.5.3b) -- already computed by tools/evaluate_experiment.py,
reused here under the 4.6 path-performance framing (note: this "Dynamic"
path is a deterministic Python heuristic, not an LLM call).

Usage: python3 tools/evaluate_section46.py <domain>
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
        "pm_simple_tsv": "nunu_all_parameter_mutation_fuzzing_attack_result_SIMPLE.tsv",
        "pm_ambiguous_tsv": "nunu_all_parameter_mutation_fuzzing_attack_result_AMBIGUOUS.tsv",
        "full_access_user": "test4",
        "limited_access_user": "test5",
    },
    "malis": {
        "ground_truth": "malis-statistics_attack_map.xlsx",
        "anonymous_tsv": "malis_all_anonymous_attack_result_final.tsv",
        "session_swap_tsv": "malis_all_session_swapping_attack_result_final.tsv",
        "pm_simple_tsv": "malis_all_parameter_mutation_fuzzing_attack_result_SIMPLE.tsv",
        "pm_ambiguous_tsv": "malis_all_parameter_mutation_fuzzing_attack_result_AMBIGUOUS.tsv",
        "full_access_user": "test9",
        "limited_access_user": "test10",
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
    f1 = (2 * precision * recall / (precision + recall)
          if (precision == precision and recall == recall and (precision + recall) > 0)
          else float("nan"))
    return {"precision": precision, "recall": recall, "specificity": specificity,
            "accuracy": accuracy, "f1": f1}


def fmt(cm, m) -> str:
    spec = "n/a" if cm["TN"] + cm["FP"] == 0 else f"{m['specificity']:.3f}"
    return (f"TP={cm['TP']} FP={cm['FP']} FN={cm['FN']} TN={cm['TN']}\n"
            f"Precision={m['precision']:.3f}  Recall={m['recall']:.3f}  "
            f"Specificity={spec}  Accuracy={m['accuracy']:.3f}  F1={m['f1']:.3f}")


def split_static_dynamic(rows_all, gt, surface, full_access_user):
    rows_t1 = [r for r in rows_all if r.get("login_info") == full_access_user]

    static_scored, dynamic_scored = [], []
    for row in rows_t1:
        ep = normalize_endpoint(row["endpoint"])
        if ep not in gt:
            continue
        status = gt[ep]["status"]
        gt_vuln = (status == "Anon") if surface == "anonymous" else (status in ("IDOR", "Anon"))

        rule_result = row["result"]
        if rule_result == "UNCERTAIN":
            pred_vuln = str(row["final_result"]).startswith("VULNERABLE")
            dynamic_scored.append((gt_vuln, "VULNERABLE" if pred_vuln else "UNAFFECTED"))
        else:
            pred_vuln = rule_result == "VULNERABLE"
            static_scored.append((gt_vuln, "VULNERABLE" if pred_vuln else "UNAFFECTED"))

    return static_scored, dynamic_scored


def eval_pm_module(rows_all, gt, full_access_user):
    rows_t1 = [r for r in rows_all if r.get("login_info") == full_access_user]
    scored = []
    for row in rows_t1:
        ep = normalize_endpoint(row["endpoint"])
        if ep not in gt:
            continue
        if row["result"] == "UNCERTAIN":
            continue
        gt_vuln = gt[ep]["status"] in ("IDOR", "Anon")
        pred_vuln = row["result"] == "VULNERABLE"
        scored.append((gt_vuln, "VULNERABLE" if pred_vuln else "UNAFFECTED"))
    return scored


def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else "nunu"
    cfg = DOMAINS[domain]

    gt = load_ground_truth(cfg["ground_truth"])
    anon_rows = load_tsv(cfg["anonymous_tsv"])
    ss_rows = load_tsv(cfg["session_swap_tsv"])
    pm_simple_rows = load_tsv(cfg["pm_simple_tsv"])
    pm_ambig_rows = load_tsv(cfg["pm_ambiguous_tsv"])

    full_user = cfg["full_access_user"]

    print(f"=== Section 4.6 -- Domain: {domain} ===\n")

    for surface_name, surface_key, rows in (
        ("Anonymous Access", "anonymous", anon_rows),
        ("Session Swapping", "session_swapping", ss_rows),
    ):
        static_scored, dynamic_scored = split_static_dynamic(rows, gt, surface_key, full_user)

        print(f"-- {surface_name} / Static (Deterministic) path -- N={len(static_scored)}")
        cm_s = confusion(static_scored)
        m_s = metrics(cm_s)
        print(fmt(cm_s, m_s))

        print(f"\n-- {surface_name} / Dynamic (Semantic/LLM) path -- N={len(dynamic_scored)}")
        cm_d = confusion(dynamic_scored)
        m_d = metrics(cm_d)
        print(fmt(cm_d, m_d))
        print()

    print("-- Parameter Mutation / Static (Deterministic, simple/Jaccard) path --")
    simple_scored = eval_pm_module(pm_simple_rows, gt, full_user)
    cm_ps = confusion(simple_scored)
    m_ps = metrics(cm_ps)
    print(f"N={len(simple_scored)}")
    print(fmt(cm_ps, m_ps))

    print("\n-- Parameter Mutation / Dynamic (Semantic, ambiguous/identity-field-diff) path --")
    print("(NOTE: this path is a deterministic Python heuristic, not an LLM call)")
    ambig_scored = eval_pm_module(pm_ambig_rows, gt, full_user)
    cm_pa = confusion(ambig_scored)
    m_pa = metrics(cm_pa)
    print(f"N={len(ambig_scored)}")
    print(fmt(cm_pa, m_pa))


if __name__ == "__main__":
    main()
