from collections import defaultdict
from statistics import mean, pstdev
from typing import Dict, List, Tuple


def compute_endpoint_series(conn_rows: List[Dict]) -> Dict[str, List[float]]:
    series = defaultdict(list)
    for d in conn_rows:
        ep = f"{d.get('id.resp_h')}:{d.get('id.resp_p')}"
        ts = d.get("ts")
        if isinstance(ts, (int, float)):
            series[ep].append(float(ts))
    for ep in series:
        series[ep].sort()
    return series


def summarize_periodicity(series: Dict[str, List[float]]) -> Dict[str, Dict]:
    out = {}
    for ep, ts in series.items():
        if len(ts) < 2:
            continue
        diffs = [b - a for a, b in zip(ts[:-1], ts[1:])]
        if not diffs:
            continue
        m = mean(diffs)
        s = pstdev(diffs) if len(diffs) > 1 else 0.0
        cv = (s / m) if m > 0 else 1e9
        out[ep] = {"count": len(ts), "period_mean": m, "period_std": s, "cv": cv}
    return out


def top_candidates(
    summary: Dict[str, Dict], min_count=5, cv_threshold=0.2, top_k=10
) -> List[Tuple[str, Dict]]:
    items = [
        (ep, stats)
        for ep, stats in summary.items()
        if stats["count"] >= min_count and stats["cv"] <= cv_threshold
    ]
    items.sort(key=lambda x: (x[1]["cv"], -x[1]["count"]))
    return items[:top_k]


def grade_beacon_answers(conn_rows: List[Dict], answers: Dict, rubric: Dict) -> Dict:
    series = compute_endpoint_series(conn_rows)
    summary = summarize_periodicity(series)
    cands = dict(
        top_candidates(
            summary,
            rubric["checks"]["min_count"],
            rubric["checks"]["cv_threshold"],
            top_k=50,
        )
    )
    tol_pct = rubric["checks"]["period_tolerance_pct"]
    required = rubric["checks"]["required_top_n"]

    results = []
    correct = 0
    for item in answers.get("beacons", []):
        ep = item["endpoint"]
        p_ans = float(item["period_sec"])
        n_ans = int(item["count"])
        s = cands.get(ep)
        if not s:
            results.append({"endpoint": ep, "ok": False, "reason": "not a candidate"})
            continue
        p_ref = float(s["period_mean"])
        n_ref = int(s["count"])
        period_ok = abs(p_ref - p_ans) <= tol_pct * p_ref
        count_ok = n_ref == n_ans
        ok = period_ok and count_ok
        if ok:
            correct += 1
        results.append(
            {
                "endpoint": ep,
                "ok": ok,
                "period": {
                    "answer": p_ans,
                    "ref": round(p_ref, 3),
                    "tol_pct": tol_pct,
                    "ok": period_ok,
                },
                "count": {"answer": n_ans, "ref": n_ref, "ok": count_ok},
            }
        )

    per_item = rubric["grading"]["per_item_points"]
    score = per_item * correct
    passed = (correct >= required) or (score >= rubric["grading"]["pass_threshold"])
    return {"score": score, "passed": passed, "details": results}
