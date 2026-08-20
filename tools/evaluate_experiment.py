#!/usr/bin/env python3
"""Evaluate KNU-MAL attack result TSVs against a domain's ground truth
statistics_attack_map.xlsx, for the nunu.local / malis.local held-out
experiment runs. Identical methodology to tools/evaluate_bab4.py +
tools/evaluate_parameter_mutation.py (endpoint normalization, login_info
filter, per-surface confusion matrix/metrics), parameterized by domain so
the same script covers both nunu and malis.

Usage: python3 tools/evaluate_experiment.py <domain>
  <domain> is "nunu" or "malis".
"""
import csv
import re
import sys
from collections import Counter
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
        gt[ep] = {
            "status": r[idx["status"]],
            "dynamic_response": str(r[idx["dynamic_response"]]).strip().lower(),
            "error_status": str(r[idx["error_status"]]).strip().lower(),
        }
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


def fmt_cm_metrics(cm, m) -> str:
    return (f"TP={cm['TP']} FP={cm['FP']} FN={cm['FN']} TN={cm['TN']}\n"
            f"Precision={m['precision']:.3f}  Recall={m['recall']:.3f}  "
            f"Specificity={m['specificity']:.3f}  Accuracy={m['accuracy']:.3f}  F1={m['f1']:.3f}")


def eval_replay_surface(rows_all, gt, surface, full_access_user, limited_access_user):
    rows_t1 = [r for r in rows_all if r.get("login_info") == full_access_user]
    rows_t2 = [r for r in rows_all if r.get("login_info") == limited_access_user]

    scored = []
    unmatched = 0
    for row in rows_t1:
        ep = normalize_endpoint(row["endpoint"])
        if ep not in gt:
            unmatched += 1
            continue
        status = gt[ep]["status"]
        gt_vuln = (status == "Anon") if surface == "anonymous" else (status in ("IDOR", "Anon"))
        pred = row["final_result"]
        pred_vuln = str(pred).startswith("VULNERABLE")
        scored.append((gt_vuln, "VULNERABLE" if pred_vuln else "UNAFFECTED"))

    cm = confusion(scored)
    m = metrics(cm)
    return {
        "total_raw": len(rows_all),
        "n_full": len(rows_t1),
        "n_limited": len(rows_t2),
        "unmatched": unmatched,
        "n_evaluated": len(scored),
        "cm": cm,
        "metrics": m,
    }


def eval_param_mutation(simple_rows_all, ambig_rows_all, gt, full_access_user):
    simple_rows = [r for r in simple_rows_all if r.get("login_info") == full_access_user]
    ambig_rows = [r for r in ambig_rows_all if r.get("login_info") == full_access_user]

    # 4.5.3a simple standalone (UNCERTAIN excluded)
    scored_s = []
    unmatched_s = 0
    uncertain_excluded = 0
    for row in simple_rows:
        ep = normalize_endpoint(row["endpoint"])
        if ep not in gt:
            unmatched_s += 1
            continue
        if row["result"] == "UNCERTAIN":
            uncertain_excluded += 1
            continue
        gt_vuln = gt[ep]["status"] in ("IDOR", "Anon")
        pred_vuln = row["result"] == "VULNERABLE"
        scored_s.append((gt_vuln, "VULNERABLE" if pred_vuln else "UNAFFECTED"))
    cm_s = confusion(scored_s)
    m_s = metrics(cm_s)

    # 4.5.3b ambiguous standalone
    scored_a = []
    unmatched_a = 0
    for row in ambig_rows:
        ep = normalize_endpoint(row["endpoint"])
        if ep not in gt:
            unmatched_a += 1
            continue
        gt_vuln = gt[ep]["status"] in ("IDOR", "Anon")
        pred_vuln = row["result"] == "VULNERABLE"
        scored_a.append((gt_vuln, "VULNERABLE" if pred_vuln else "UNAFFECTED"))
    cm_a = confusion(scored_a)
    m_a = metrics(cm_a)

    # 4.5.3c combined full pipeline
    ambig_by_ep = {normalize_endpoint(r["endpoint"]): r for r in ambig_rows}
    scored_c = []
    unmatched_c = 0
    resolved_by_simple = 0
    resolved_by_ambig = 0
    for row in simple_rows:
        ep = normalize_endpoint(row["endpoint"])
        if ep not in gt:
            unmatched_c += 1
            continue
        gt_vuln = gt[ep]["status"] in ("IDOR", "Anon")
        if row["result"] == "UNCERTAIN":
            llm_row = ambig_by_ep.get(ep)
            if llm_row is None:
                continue
            pred_vuln = llm_row["result"] == "VULNERABLE"
            resolved_by_ambig += 1
        else:
            pred_vuln = row["result"] == "VULNERABLE"
            resolved_by_simple += 1
        scored_c.append((gt_vuln, "VULNERABLE" if pred_vuln else "UNAFFECTED"))
    cm_c = confusion(scored_c)
    m_c = metrics(cm_c)

    return {
        "simple": {"n_total": len(simple_rows_all), "n_full": len(simple_rows),
                   "n_evaluated": len(scored_s), "unmatched": unmatched_s,
                   "uncertain_excluded": uncertain_excluded, "cm": cm_s, "metrics": m_s},
        "ambiguous": {"n_total": len(ambig_rows_all), "n_full": len(ambig_rows),
                      "n_evaluated": len(scored_a), "unmatched": unmatched_a,
                      "cm": cm_a, "metrics": m_a},
        "combined": {"n_evaluated": len(scored_c), "unmatched": unmatched_c,
                     "resolved_by_simple": resolved_by_simple,
                     "resolved_by_ambiguous": resolved_by_ambig,
                     "cm": cm_c, "metrics": m_c},
    }


def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else "nunu"
    cfg = DOMAINS[domain]

    gt = load_ground_truth(cfg["ground_truth"])
    anon_rows = load_tsv(cfg["anonymous_tsv"])
    ss_rows = load_tsv(cfg["session_swap_tsv"])
    pm_simple_rows = load_tsv(cfg["pm_simple_tsv"])
    pm_ambig_rows = load_tsv(cfg["pm_ambiguous_tsv"])

    full_user = cfg["full_access_user"]
    limited_user = cfg["limited_access_user"]

    print(f"=== Domain: {domain} ({cfg['ground_truth']}, N ground truth = {len(gt)}) ===")
    print(f"Full-access login_info = {full_user}, limited-access login_info = {limited_user}\n")

    anon_eval = eval_replay_surface(anon_rows, gt, "anonymous", full_user, limited_user)
    ss_eval = eval_replay_surface(ss_rows, gt, "session_swapping", full_user, limited_user)
    pm_eval = eval_param_mutation(pm_simple_rows, pm_ambig_rows, gt, full_user)

    print("--- 4.5.1 Anonymous Access ---")
    print(f"Total TSV rows: {anon_eval['total_raw']} ({full_user}={anon_eval['n_full']}, "
          f"{limited_user}={anon_eval['n_limited']})")
    print(f"Evaluated N = {anon_eval['n_evaluated']} (unmatched={anon_eval['unmatched']})")
    print(fmt_cm_metrics(anon_eval["cm"], anon_eval["metrics"]))

    print("\n--- 4.5.2 Session Swapping ---")
    print(f"Total TSV rows: {ss_eval['total_raw']} ({full_user}={ss_eval['n_full']}, "
          f"{limited_user}={ss_eval['n_limited']})")
    print(f"Evaluated N = {ss_eval['n_evaluated']} (unmatched={ss_eval['unmatched']})")
    print(fmt_cm_metrics(ss_eval["cm"], ss_eval["metrics"]))

    print("\n--- 4.5.3a Parameter Mutation SIMPLE (standalone) ---")
    s = pm_eval["simple"]
    print(f"Evaluated N = {s['n_evaluated']} (unmatched={s['unmatched']}, "
          f"UNCERTAIN excluded={s['uncertain_excluded']})")
    print(fmt_cm_metrics(s["cm"], s["metrics"]))

    print("\n--- 4.5.3b Parameter Mutation AMBIGUOUS (standalone) ---")
    a = pm_eval["ambiguous"]
    print(f"Evaluated N = {a['n_evaluated']} (unmatched={a['unmatched']})")
    print(fmt_cm_metrics(a["cm"], a["metrics"]))

    print("\n--- 4.5.3c Parameter Mutation COMBINED FULL PIPELINE ---")
    c = pm_eval["combined"]
    print(f"Evaluated N = {c['n_evaluated']} (unmatched={c['unmatched']}, "
          f"resolved_by_simple={c['resolved_by_simple']}, resolved_by_ambiguous={c['resolved_by_ambiguous']})")
    print(fmt_cm_metrics(c["cm"], c["metrics"]))

    print("\n--- 4.7 Aggregate (Anonymous + Session Swapping + Parameter Mutation combined) ---")
    agg_cm = {
        "TP": anon_eval["cm"]["TP"] + ss_eval["cm"]["TP"] + c["cm"]["TP"],
        "FP": anon_eval["cm"]["FP"] + ss_eval["cm"]["FP"] + c["cm"]["FP"],
        "FN": anon_eval["cm"]["FN"] + ss_eval["cm"]["FN"] + c["cm"]["FN"],
        "TN": anon_eval["cm"]["TN"] + ss_eval["cm"]["TN"] + c["cm"]["TN"],
    }
    agg_m = metrics(agg_cm)
    agg_n = anon_eval["n_evaluated"] + ss_eval["n_evaluated"] + c["n_evaluated"]
    print(f"Evaluated N = {agg_n}")
    print(fmt_cm_metrics(agg_cm, agg_m))


if __name__ == "__main__":
    main()
