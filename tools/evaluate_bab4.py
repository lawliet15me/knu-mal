#!/usr/bin/env python3
"""Evaluate KNU-MAL attack result TSVs against statistics_attack_map.xlsx and
print every metric needed for Bab 4 (4.4.2/Table 4.5, 4.5, 4.6, 4.7, 4.9.3) as
plain text, plus the login_info=test1 filtered breakdown.

Ground truth source: statistics_attack_map.xlsx, sheet "Attack Map" (900 rows,
exported directly from the malis.local application -- supersedes the earlier
ground_truth.xlsx, cross-validated to match it 100% on Safe/Vulnerable labels).
Columns used:
    - endpoint            : templated endpoint (uses "/{id}" placeholders)
    - status              : IDOR (446) / Safe (270) / Anon (184)
    - dynamic_response    : "yes"/"no" -- whether the APPLICATION's response
                             for this endpoint inherently contains volatile
                             fields (token/timestamp/signature), independent
                             of which attack surface is used to test it. This
                             is the authoritative Static/Dynamic source for
                             Table 4.5 (534 "no"=Static / 366 "yes"=Dynamic,
                             matching the thesis draft's N=900 split exactly).
    - error_status        : "vulnerable" (630) / "safe always http 200" (150)
                             / "safe standard error" (120) -- the 3-way Table
                             4.5 classification bucket per endpoint.
    - ground_truth        : "Vulnerable"/"Safe" -- redundant with `status`.

Per-surface ground truth used for scoring (same as before):
    - Anonymous Access surface : vulnerable iff status == "Anon"            (184 vuln / 716 safe)
    - Session Swapping surface : vulnerable iff status in ("IDOR", "Anon")  (630 vuln / 270 safe)

IMPORTANT -- login_info=test1 filter:
The two attack-result TSVs replay requests captured from TWO users: test1
(901 endpoints, full access) and test2 (11 endpoints, limited access, ~10 of
which are adjacent/overlapping with test1's own menu -- see Section 4.4).
statistics_attack_map.xlsx's 900 rows are exported as test1's menu ONLY. If
test2's 11 rows are left in the evaluation, the evaluated population no
longer matches the 900-row ground truth 1:1 (some of test2's requests target
endpoints structurally identical to test1's but are not independently listed
in the ground truth, and one is genuinely out of scope). Therefore ALL
scoring in this script filters to login_info == "test1" first -- this must be
stated explicitly in the Bab 4 methodology text, since without the filter the
"N=900" evaluated population silently drifts.

TSV endpoints carry literal path-param values (e.g. ".../restore-database/1")
while the ground truth stores templated endpoints (".../restore-database" or
".../profile/{id}"). normalize_endpoint() strips a trailing "/{...}" OR a
trailing "/<digits>" segment, plus any query string, to align the two.
"""
import csv
import re
import sys
from typing import Dict, List, Tuple

import openpyxl

GROUND_TRUTH_PATH = "statistics_attack_map.xlsx"
ANONYMOUS_TSV = "api_malis_local_anonymous_attack_result_final.tsv"
SESSION_SWAP_TSV = "api_malis_local_session_swapping_attack_result_final.tsv"


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
            "dynamic_response": str(r[idx["dynamic_response"]]).strip().lower(),  # yes/no
            "error_status": str(r[idx["error_status"]]).strip().lower(),
        }
    return gt


def load_tsv(path: str) -> List[dict]:
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter="\t")
        return list(reader)


def filter_test1(rows: List[dict]) -> List[dict]:
    return [r for r in rows if r.get("login_info") == "test1"]


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
    """tsv_rows MUST already be filtered to login_info == 'test1'."""

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


def section_login_info_test1(gt, anon_rows, ss_rows):
    print_section("FILTER login_info = test1 (rekonsiliasi populasi evaluasi)")
    print(
        "Kedua TSV hasil serangan merekam request dari DUA user: test1 (901\n"
        "endpoint, akses penuh) dan test2 (11 endpoint, akses terbatas, 10 di\n"
        "antaranya adjacent/overlap dengan menu test1, 1 out-of-scope -- lihat\n"
        "Section 4.4). statistics_attack_map.xlsx (ground truth) hanya berisi\n"
        "900 baris untuk menu test1. Tanpa memfilter login_info=test1, populasi\n"
        "yang dievaluasi TIDAK LAGI 1:1 dengan 900 baris ground truth -- maka\n"
        "SELURUH evaluasi pada dokumen ini memfilter login_info=test1 terlebih\n"
        "dahulu sebelum dibandingkan dengan ground truth."
    )

    for surface_name, rows_, field in (("Anonymous Access", anon_rows, "result"),
                                        ("Session Swapping", ss_rows, "result")):
        total_raw = len(rows_)
        t1_rows = filter_test1(rows_)
        t2_rows = [r for r in rows_ if r.get("login_info") == "test2"]

        matched = sum(1 for r in t1_rows if normalize_endpoint(r["endpoint"]) in gt)
        unmatched = len(t1_rows) - matched

        from collections import Counter
        result_dist = Counter(r["result"] for r in t1_rows)
        final_dist = Counter(r["final_result"] for r in t1_rows)

        print(f"\n-- {surface_name} --")
        print(f"Total baris TSV (semua user)      : {total_raw}")
        print(f"  login_info=test1                : {len(t1_rows)}  (matched ground truth={matched}, unmatched={unmatched})")
        print(f"  login_info=test2 (DIKELUARKAN)   : {len(t2_rows)}")
        print(f"Rule-based result (before LLM), login_info=test1 only:")
        for k in ("VULNERABLE", "UNCERTAIN", "UNAFFECTED"):
            v = result_dist.get(k, 0)
            print(f"    {k:<12} = {v}")
        print(f"Final result (after LLM), login_info=test1 only:")
        for k in ("VULNERABLE", "UNAFFECTED"):
            v = final_dist.get(k, 0)
            print(f"    {k:<12} = {v}")


def section_table_4_5(gt, anon_rows_t1, ss_rows_t1):
    print_section("TABLE 4.5 (diperluas) -- Response classification x reasoning path x hasil deteksi")
    print(
        "Sumber Static/Dynamic dan bucket (Vulnerable / Safe-Always200 /\n"
        "Safe-StandardError): kolom dynamic_response & error_status di\n"
        "statistics_attack_map.xlsx (properti desain aplikasi per endpoint,\n"
        "N=900, TIDAK bergantung pada surface serangan). 3 kolom tambahan di\n"
        "bawah menunjukkan, UNTUK SETIAP baris klasifikasi Table 4.5, berapa\n"
        "endpoint yang match ground truth (ditemukan/benar) vs meleset (gagal)\n"
        "-- dihitung terpisah per surface serangan (Anonymous Access, Session\n"
        "Swapping), karena hasil deteksi aktual berbeda per surface meski\n"
        "baseline Static/Dynamic-nya sama."
    )

    def bucket_of(ep_gt):
        dyn = ep_gt["dynamic_response"] == "yes"
        err = ep_gt["error_status"]
        path = "Dynamic" if dyn else "Static"
        if err == "vulnerable":
            cls = "Vulnerable"
        elif err == "safe always http 200":
            cls = "Safe-Always200"
        elif err == "safe standard error":
            cls = "Safe-StandardError"
        else:
            cls = f"UNKNOWN({err})"
        return path, cls

    buckets = ["Static|Vulnerable", "Static|Safe-Always200", "Static|Safe-StandardError",
               "Dynamic|Vulnerable", "Dynamic|Safe-Always200", "Dynamic|Safe-StandardError"]

    bucket_counts = {b: 0 for b in buckets}
    for ep_gt in gt.values():
        path, cls = bucket_of(ep_gt)
        bucket_counts[f"{path}|{cls}"] += 1

    def eval_surface(rows_t1, surface):
        idx_by_ep = {normalize_endpoint(r["endpoint"]): r for r in rows_t1}
        det_match = {b: 0 for b in buckets}
        det_total = {b: 0 for b in buckets}
        llm_match = {b: 0 for b in buckets}
        llm_total = {b: 0 for b in buckets}
        final_match = {b: 0 for b in buckets}
        final_total = {b: 0 for b in buckets}

        for ep, ep_gt in gt.items():
            path, cls = bucket_of(ep_gt)
            b = f"{path}|{cls}"
            row = idx_by_ep.get(ep)
            if row is None:
                continue

            status = ep_gt["status"]
            gt_vuln = (status == "Anon") if surface == "anonymous" else (status in ("IDOR", "Anon"))

            # Deterministic (rule-based `result`) -- only meaningful for rows
            # NOT UNCERTAIN; UNCERTAIN rows have no deterministic verdict.
            if row["result"] != "UNCERTAIN":
                det_total[b] += 1
                pred_vuln = row["result"] == "VULNERABLE"
                if pred_vuln == gt_vuln:
                    det_match[b] += 1

            # LLM (only meaningful for rows that WERE UNCERTAIN, i.e. got a
            # real llm_similarity_score)
            if row["result"] == "UNCERTAIN" and row.get("llm_similarity_score", "-") != "-":
                llm_total[b] += 1
                pred_vuln = str(row["final_result"]).startswith("VULNERABLE")
                if pred_vuln == gt_vuln:
                    llm_match[b] += 1

            # Combined final_result -- every row
            final_total[b] += 1
            pred_vuln = str(row["final_result"]).startswith("VULNERABLE")
            if pred_vuln == gt_vuln:
                final_match[b] += 1

        return det_match, det_total, llm_match, llm_total, final_match, final_total

    anon_eval = eval_surface(anon_rows_t1, "anonymous")
    ss_eval = eval_surface(ss_rows_t1, "session_swapping")

    COLW = 18
    header = (f"{'Reasoning Path':<10}{'Classification':<22}{'N(GT)':>7}  |  "
              f"{'Anon Det':>{COLW}}{'Anon LLM':>{COLW}}{'Anon Final':>{COLW}}  |  "
              f"{'SS Det':>{COLW}}{'SS LLM':>{COLW}}{'SS Final':>{COLW}}")
    print("\n" + header)
    print("-" * len(header))

    def fmt_cell(match, total):
        if total == 0:
            return "n/a"
        return f"{match}/{total} ({match/total*100:.1f}%)"

    total_n = 0
    for b in buckets:
        path, cls = b.split("|")
        n_gt = bucket_counts[b]
        total_n += n_gt

        a_det_m, a_det_t, a_llm_m, a_llm_t, a_fin_m, a_fin_t = anon_eval
        s_det_m, s_det_t, s_llm_m, s_llm_t, s_fin_m, s_fin_t = ss_eval

        row_str = (f"{path:<10}{cls:<22}{n_gt:>7}  |  "
                   f"{fmt_cell(a_det_m[b], a_det_t[b]):>{COLW}}{fmt_cell(a_llm_m[b], a_llm_t[b]):>{COLW}}"
                   f"{fmt_cell(a_fin_m[b], a_fin_t[b]):>{COLW}}  |  "
                   f"{fmt_cell(s_det_m[b], s_det_t[b]):>{COLW}}{fmt_cell(s_llm_m[b], s_llm_t[b]):>{COLW}}"
                   f"{fmt_cell(s_fin_m[b], s_fin_t[b]):>{COLW}}")
        print(row_str)

    print("-" * len(header))
    print(f"{'TOTAL':<32}{total_n:>7}")

    static_n = sum(bucket_counts[b] for b in buckets if b.startswith("Static"))
    dynamic_n = sum(bucket_counts[b] for b in buckets if b.startswith("Dynamic"))
    print(f"\nStatic (Deterministic)  total N = {static_n} ({static_n/900*100:.1f}%)")
    print(f"Dynamic (Semantic/LLM)  total N = {dynamic_n} ({dynamic_n/900*100:.1f}%)")


def main():
    gt = load_ground_truth()
    anon_rows_all = load_tsv(ANONYMOUS_TSV)
    ss_rows_all = load_tsv(SESSION_SWAP_TSV)

    section_login_info_test1(gt, anon_rows_all, ss_rows_all)

    anon_rows = filter_test1(anon_rows_all)
    ss_rows = filter_test1(ss_rows_all)

    section_table_4_5(gt, anon_rows, ss_rows)

    print_section("4.5.1 CREDENTIAL-LEVEL SUBSTITUTION (ANONYMOUS ACCESS)")
    scored, excl, unmatched = build_rows(anon_rows, gt, "anonymous", "final_result", use_final=True)
    cm = confusion(scored)
    m = metrics(cm)
    print(f"Evaluated N = {len(scored)}  (excluded unmatched = {unmatched})")
    print(f"Confusion matrix: TP={cm['TP']} FP={cm['FP']} FN={cm['FN']} TN={cm['TN']}")
    print(fmt_metrics(m))

    print_section("4.5.2 SESSION-LEVEL SUBSTITUTION (SESSION SWAPPING)")
    scored_ss, excl_ss, unmatched_ss = build_rows(ss_rows, gt, "session_swapping", "final_result", use_final=True)
    cm_ss = confusion(scored_ss)
    m_ss = metrics(cm_ss)
    print(f"Evaluated N = {len(scored_ss)}  (excluded unmatched = {unmatched_ss})")
    print(f"Confusion matrix: TP={cm_ss['TP']} FP={cm_ss['FP']} FN={cm_ss['FN']} TN={cm_ss['TN']}")
    print(fmt_metrics(m_ss))
    if cm_ss["FN"] > 0:
        artifact_fn = 0
        genuine_fn = 0
        for row in ss_rows:
            ep_norm = normalize_endpoint(row["endpoint"])
            if ep_norm not in gt:
                continue
            status = gt[ep_norm]["status"]
            if status not in ("IDOR", "Anon"):
                continue
            pred = row["final_result"]
            if str(pred).startswith("VULNERABLE"):
                continue
            if row.get("current_resp_code", "") == "" and row.get("login_info") == row.get("source_user"):
                artifact_fn += 1
            else:
                genuine_fn += 1
        denom = cm_ss['TP'] + artifact_fn + genuine_fn
        corrected = (cm_ss['TP'] + artifact_fn) / denom if denom else float("nan")
        print(f"[Note] Of {cm_ss['FN']} FN: {artifact_fn} attributable to the is_source_user_record "
              f"test-harness artifact (hardcoded UNAFFECTED, no HTTP request sent) -- corrected Recall "
              f"excluding these = {corrected:.3f}. The remaining {genuine_fn} FN are genuine LLM-triage "
              f"misses (UNCERTAIN rows scored below the SIMILARITY_VULNERABLE_THRESHOLD).")

    print_section("4.6 DETERMINISTIC VS SEMANTIC PATH PERFORMANCE")
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

    print_section("4.7 AGGREGATE CROSS-SURFACE RESULTS (Anonymous + Session Swapping combined)")
    combined = scored + scored_ss
    cm_all = confusion(combined)
    m_all = metrics(cm_all)
    print(f"Evaluated N = {len(combined)}")
    print(f"Confusion matrix: TP={cm_all['TP']} FP={cm_all['FP']} FN={cm_all['FN']} TN={cm_all['TN']}")
    print(fmt_metrics(m_all))
    print("\nNaive all-vulnerable baseline (Table 3.1): Precision=0.700 Specificity=0.000")

    print_section("4.9.3 RULE-ONLY VS FULL-PIPELINE CONFUSION MATRIX COMPARISON")
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
