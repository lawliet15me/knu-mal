#!/usr/bin/env python3
"""Evaluate KNU-MAL attack result TSVs (nunu.local test-set run) against
statistics_attack_map_nunu-local.xlsx. Identical logic to
tools/evaluate_bab4.py, adapted for the second (held-out) dataset:
    - login_info filter: test6 (full access, analogous to test1) instead of
      test1; test7 (limited access, analogous to test2) is excluded, same
      rationale as the original script.
    - Ground truth: statistics_attack_map_nunu-local.xlsx (same column
      schema as statistics_attack_map.xlsx, verified identical: endpoint,
      parameter_name, param_location, status, dynamic_response,
      error_status, ground_truth, attack_simulation).
    - No code/threshold/prompt changes were made to the framework itself --
      this is a pure held-out re-run against a second dataset whose JSON
      Pattern/Error Pattern/Extra Params differ from the training set, but
      whose vulnerability labels (status column) are identical row-for-row.

See tools/evaluate_bab4.py for full docstring/rationale (login_info filter
methodology, endpoint normalization, etc.) -- not repeated here.
"""
import csv
import re
import sys
from typing import Dict, List, Tuple

import openpyxl

GROUND_TRUTH_PATH = "statistics_attack_map_nunu-local.xlsx"
ANONYMOUS_TSV = "all_anonymous_attack_result_final.tsv"
SESSION_SWAP_TSV = "all_session_swapping_attack_result_final.tsv"
FULL_ACCESS_USER = "test6"
LIMITED_ACCESS_USER = "test7"


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
        gt[ep] = {
            "status": r[idx["status"]],  # IDOR / Safe / Anon
            "dynamic_response": str(r[idx["dynamic_response"]]).strip().lower(),
            "error_status": str(r[idx["error_status"]]).strip().lower(),
        }
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


def build_rows(tsv_rows: List[dict], gt: Dict[str, dict], surface: str,
               result_field: str, use_final: bool) -> Tuple[List[Tuple[bool, str]], int, int]:
    scored = []
    excluded_uncertain = 0
    unmatched = 0

    for row in tsv_rows:
        ep_norm = normalize_endpoint(row["endpoint"])
        if ep_norm not in gt:
            unmatched += 1
            continue

        raw_result = row["result"]
        pred = row[result_field] if use_final else raw_result

        if not use_final and raw_result == "UNCERTAIN":
            excluded_uncertain += 1
            continue

        status = gt[ep_norm]["status"]
        if surface == "anonymous":
            gt_vuln = (status == "Anon")
        else:
            gt_vuln = (status in ("IDOR", "Anon"))

        pred_norm = "VULNERABLE" if str(pred).startswith("VULNERABLE") else "UNAFFECTED"
        scored.append((gt_vuln, pred_norm))

    return scored, excluded_uncertain, unmatched


def print_section(title: str):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def section_login_info_filter(gt, anon_rows, ss_rows):
    print_section(f"FILTER login_info = {FULL_ACCESS_USER} (rekonsiliasi populasi evaluasi, dataset nunu.local)")
    for surface_name, rows_, field in (("Anonymous Access", anon_rows, "result"),
                                        ("Session Swapping", ss_rows, "result")):
        total_raw = len(rows_)
        full_rows = filter_full_access(rows_)
        limited_rows = [r for r in rows_ if r.get("login_info") == LIMITED_ACCESS_USER]

        matched = sum(1 for r in full_rows if normalize_endpoint(r["endpoint"]) in gt)
        unmatched = len(full_rows) - matched

        from collections import Counter
        result_dist = Counter(r["result"] for r in full_rows)
        final_dist = Counter(r["final_result"] for r in full_rows)

        print(f"\n-- {surface_name} --")
        print(f"Total baris TSV (semua user)      : {total_raw}")
        print(f"  login_info={FULL_ACCESS_USER}                : {len(full_rows)}  (matched ground truth={matched}, unmatched={unmatched})")
        print(f"  login_info={LIMITED_ACCESS_USER} (DIKELUARKAN)   : {len(limited_rows)}")
        print(f"Rule-based result (before LLM), login_info={FULL_ACCESS_USER} only:")
        for k in ("VULNERABLE", "UNCERTAIN", "UNAFFECTED"):
            v = result_dist.get(k, 0)
            print(f"    {k:<12} = {v}")
        print(f"Final result (after LLM), login_info={FULL_ACCESS_USER} only:")
        for k in ("VULNERABLE", "UNAFFECTED"):
            v = final_dist.get(k, 0)
            print(f"    {k:<12} = {v}")


def main():
    gt = load_ground_truth()
    anon_rows_all = load_tsv(ANONYMOUS_TSV)
    ss_rows_all = load_tsv(SESSION_SWAP_TSV)

    section_login_info_filter(gt, anon_rows_all, ss_rows_all)

    anon_rows = filter_full_access(anon_rows_all)
    ss_rows = filter_full_access(ss_rows_all)

    print_section("4.5.1 CREDENTIAL-LEVEL SUBSTITUTION (ANONYMOUS ACCESS) -- nunu.local test-set")
    scored, excl, unmatched = build_rows(anon_rows, gt, "anonymous", "final_result", use_final=True)
    cm = confusion(scored)
    m = metrics(cm)
    print(f"Evaluated N = {len(scored)}  (excluded unmatched = {unmatched})")
    print(f"Confusion matrix: TP={cm['TP']} FP={cm['FP']} FN={cm['FN']} TN={cm['TN']}")
    print(fmt_metrics(m))

    print_section("4.5.2 SESSION-LEVEL SUBSTITUTION (SESSION SWAPPING) -- nunu.local test-set")
    scored_ss, excl_ss, unmatched_ss = build_rows(ss_rows, gt, "session_swapping", "final_result", use_final=True)
    cm_ss = confusion(scored_ss)
    m_ss = metrics(cm_ss)
    print(f"Evaluated N = {len(scored_ss)}  (excluded unmatched = {unmatched_ss})")
    print(f"Confusion matrix: TP={cm_ss['TP']} FP={cm_ss['FP']} FN={cm_ss['FN']} TN={cm_ss['TN']}")
    print(fmt_metrics(m_ss))

    print_section("4.6 DETERMINISTIC VS SEMANTIC PATH PERFORMANCE -- nunu.local test-set")
    for surface, rows_ in (("anonymous", anon_rows), ("session_swapping", ss_rows)):
        static_rows = []
        dynamic_rows = []
        for row in rows_:
            ep_norm = normalize_endpoint(row["endpoint"])
            if ep_norm not in gt:
                continue
            status = gt[ep_norm]["status"]
            gt_vuln = (status == "Anon") if surface == "anonymous" else (status in ("IDOR", "Anon"))
            raw_result = row["result"]
            if raw_result == "UNCERTAIN":
                pred = row["final_result"]
                pred_norm = "VULNERABLE" if str(pred).startswith("VULNERABLE") else "UNAFFECTED"
                dynamic_rows.append((gt_vuln, pred_norm))
            else:
                pred_norm = "VULNERABLE" if raw_result == "VULNERABLE" else "UNAFFECTED"
                static_rows.append((gt_vuln, pred_norm))
        cm_static = confusion(static_rows)
        cm_dynamic = confusion(dynamic_rows)
        print(f"\n-- {surface} / Static (Deterministic) path -- N={len(static_rows)}")
        print(f"   TP={cm_static['TP']} FP={cm_static['FP']} FN={cm_static['FN']} TN={cm_static['TN']}  " + fmt_metrics(metrics(cm_static)))
        print(f"-- {surface} / Dynamic (Semantic/LLM) path -- N={len(dynamic_rows)}")
        print(f"   TP={cm_dynamic['TP']} FP={cm_dynamic['FP']} FN={cm_dynamic['FN']} TN={cm_dynamic['TN']}  " + fmt_metrics(metrics(cm_dynamic)))

    print_section("4.7a AGGREGATE (Anonymous + Session Swapping combined) -- nunu.local test-set")
    combined = scored + scored_ss
    cm_all = confusion(combined)
    m_all = metrics(cm_all)
    print(f"Evaluated N = {len(combined)}")
    print(f"Confusion matrix: TP={cm_all['TP']} FP={cm_all['FP']} FN={cm_all['FN']} TN={cm_all['TN']}")
    print(fmt_metrics(m_all))
    print("\nNaive all-vulnerable baseline (Table 3.1): Precision=0.700 Specificity=0.000")

    print_section("4.9.3 RULE-ONLY VS FULL-PIPELINE COMPARISON -- nunu.local test-set")
    for surface, rows_ in (("Anonymous Access", anon_rows), ("Session Swapping", ss_rows)):
        surf_key = "anonymous" if surface == "Anonymous Access" else "session_swapping"
        rule_only, excl_u, unmatched_r = build_rows(rows_, gt, surf_key, "result", use_final=False)
        full_pipeline, _, unmatched_f = build_rows(rows_, gt, surf_key, "final_result", use_final=True)

        cm_rule = confusion(rule_only)
        cm_full = confusion(full_pipeline)
        m_rule = metrics(cm_rule)
        m_full = metrics(cm_full)

        print(f"\n-- {surface} --")
        print(f"Rule-only     : N={len(rule_only)} (excluded UNCERTAIN={excl_u}, unmatched={unmatched_r})")
        print(f"                TP={cm_rule['TP']} FP={cm_rule['FP']} FN={cm_rule['FN']} TN={cm_rule['TN']}  " + fmt_metrics(m_rule))
        print(f"Full pipeline : N={len(full_pipeline)} (unmatched={unmatched_f})")
        print(f"                TP={cm_full['TP']} FP={cm_full['FP']} FN={cm_full['FN']} TN={cm_full['TN']}  " + fmt_metrics(m_full))
        delta = (m_full['recall'] - m_rule['recall']) * 100 if m_rule['recall'] == m_rule['recall'] else float('nan')
        print(f"Recall delta (full - rule-only): {delta:+.1f} percentage points")


if __name__ == "__main__":
    main()
