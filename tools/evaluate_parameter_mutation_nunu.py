#!/usr/bin/env python3
"""Evaluate parameter_mutation_fuzzing (simple + ambiguous/field-diff) results
on the nunu.local test-set run against statistics_attack_map_nunu-local.xlsx.
Adapted from tools/evaluate_parameter_mutation.py -- same logic, different
target files and login_info values (test6=full access, test7=limited access,
analogous to test1/test2 in the original training-set run).
"""
import csv
import re
from typing import Dict, List, Tuple

import openpyxl

GROUND_TRUTH_PATH = "statistics_attack_map_nunu-local.xlsx"
SIMPLE_TSV = "all_parameter_mutation_fuzzing_attack_result_SIMPLE.tsv"
AMBIGUOUS_TSV = "all_parameter_mutation_fuzzing_attack_result_AMBIGUOUS.tsv"
FULL_ACCESS_USER = "test6"


def normalize_endpoint(ep: str) -> str:
    ep = ep.strip().split("?")[0]
    ep = re.sub(r"/\{[^}]+\}$", "", ep)
    ep = re.sub(r"/\d+$", "", ep)
    return ep


def load_ground_truth() -> Dict[str, dict]:
    wb = openpyxl.load_workbook(GROUND_TRUTH_PATH, data_only=True)
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


def filter_full_access(rows: List[dict]) -> List[dict]:
    return [r for r in rows if r.get("login_info") == FULL_ACCESS_USER]


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


def fmt_metrics(m: Dict[str, float]) -> str:
    return (f"Precision={m['precision']:.3f}  Recall={m['recall']:.3f}  "
            f"Specificity={m['specificity']:.3f}  Accuracy={m['accuracy']:.3f}  F1={m['f1']:.3f}")


def print_section(title: str):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def main():
    gt = load_ground_truth()
    simple_rows_all = load_tsv(SIMPLE_TSV)
    ambig_rows_all = load_tsv(AMBIGUOUS_TSV)

    simple_rows = filter_full_access(simple_rows_all)
    ambig_rows = filter_full_access(ambig_rows_all)

    print_section(f"Rekonsiliasi populasi (login_info={FULL_ACCESS_USER} filter) -- nunu.local test-set")
    print(f"Simple: total={len(simple_rows_all)}, {FULL_ACCESS_USER}={len(simple_rows)}, "
          f"excluded={len(simple_rows_all) - len(simple_rows)}")
    print(f"Ambiguous: total={len(ambig_rows_all)}, {FULL_ACCESS_USER}={len(ambig_rows)}, "
          f"excluded={len(ambig_rows_all) - len(ambig_rows)}")

    print_section("4.5.3a SIMPLE (Deterministic/Jaccard) -- standalone, UNCERTAIN excluded -- nunu.local test-set")
    scored = []
    unmatched = 0
    uncertain_excluded = 0
    for row in simple_rows:
        ep = normalize_endpoint(row["endpoint"])
        if ep not in gt:
            unmatched += 1
            continue
        if row["result"] == "UNCERTAIN":
            uncertain_excluded += 1
            continue
        gt_vuln = gt[ep]["status"] in ("IDOR", "Anon")
        pred_vuln = row["result"] == "VULNERABLE"
        scored.append((gt_vuln, "VULNERABLE" if pred_vuln else "UNAFFECTED"))
    cm = confusion(scored)
    m = metrics(cm)
    print(f"Evaluated N = {len(scored)} (unmatched={unmatched}, UNCERTAIN excluded={uncertain_excluded})")
    print(f"TP={cm['TP']} FP={cm['FP']} FN={cm['FN']} TN={cm['TN']}")
    print(fmt_metrics(m))

    print_section("4.5.3b AMBIGUOUS (Structural pre-check + identity-field-diff) -- standalone -- nunu.local test-set")
    scored_ambig = []
    unmatched_a = 0
    for row in ambig_rows:
        ep = normalize_endpoint(row["endpoint"])
        if ep not in gt:
            unmatched_a += 1
            continue
        gt_vuln = gt[ep]["status"] in ("IDOR", "Anon")
        pred_vuln = row["result"] == "VULNERABLE"
        scored_ambig.append((gt_vuln, "VULNERABLE" if pred_vuln else "UNAFFECTED"))
    cm_a = confusion(scored_ambig)
    m_a = metrics(cm_a)
    print(f"Evaluated N = {len(scored_ambig)} (unmatched={unmatched_a})")
    print(f"TP={cm_a['TP']} FP={cm_a['FP']} FN={cm_a['FN']} TN={cm_a['TN']}")
    print(fmt_metrics(m_a))

    print_section("4.5.3c COMBINED FULL PIPELINE (simple decisive rows + ambiguous-resolved UNCERTAIN rows) -- nunu.local test-set")

    ambig_by_ep = {}
    for row in ambig_rows:
        ep = normalize_endpoint(row["endpoint"])
        ambig_by_ep[ep] = row

    combined_scored = []
    combined_unmatched = 0
    resolved_by_ambig = 0
    resolved_by_simple = 0

    for row in simple_rows:
        ep = normalize_endpoint(row["endpoint"])
        if ep not in gt:
            combined_unmatched += 1
            continue
        gt_vuln = gt[ep]["status"] in ("IDOR", "Anon")

        if row["result"] == "UNCERTAIN":
            ambig_row = ambig_by_ep.get(ep)
            if ambig_row is None:
                continue
            pred_vuln = ambig_row["result"] == "VULNERABLE"
            resolved_by_ambig += 1
        else:
            pred_vuln = row["result"] == "VULNERABLE"
            resolved_by_simple += 1

        combined_scored.append((gt_vuln, "VULNERABLE" if pred_vuln else "UNAFFECTED"))

    cm_c = confusion(combined_scored)
    m_c = metrics(cm_c)
    print(f"Evaluated N = {len(combined_scored)} (unmatched={combined_unmatched})")
    print(f"  resolved by simple (deterministic):              {resolved_by_simple}")
    print(f"  resolved by ambiguous (identity-field-diff):     {resolved_by_ambig}")
    print(f"TP={cm_c['TP']} FP={cm_c['FP']} FN={cm_c['FN']} TN={cm_c['TN']}")
    print(fmt_metrics(m_c))

    print("\nNaive all-vulnerable baseline for this surface: Precision=0.700 Specificity=0.000")


if __name__ == "__main__":
    main()
