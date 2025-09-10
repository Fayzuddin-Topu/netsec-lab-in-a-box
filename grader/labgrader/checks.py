from collections import defaultdict
from statistics import mean, pstdev
from typing import Dict, List, Tuple
from pathlib import Path
import json


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


# --- TLS helpers (Lab 02) ---


def _iter_zeek_tsv(path: Path):
    """
    Minimal Zeek ASCII (TSV) reader. Honors '#fields' header.
    Yields dicts for each row.
    """
    if not path.exists():
        return
    fields = None
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            parts = line.rstrip("\n").split("\t")
            if fields and len(parts) == len(fields):
                yield dict(zip(fields, parts))


def _alpn_counts_from_zeek_ssl(log_dir: Path) -> Dict[str, int]:
    """
    Prefer Zeek ssl.log for ALPN (field: next_protocol).
    Returns dict like {'h2': 12, 'http/1.1': 8, 'acme-tls/1': 2}.
    """
    counts: Dict[str, int] = {}
    p = log_dir / "zeek" / "ssl.log"
    for row in _iter_zeek_tsv(p):
        np = (row.get("next_protocol") or "").strip()
        if np and np != "-":
            counts[np] = counts.get(np, 0) + 1
    return counts


def _alpn_counts_from_suricata(log_dir: Path) -> Dict[str, int]:
    """
    Optional fallback: read ALPN from Suricata EVE (tls.alpn or tls.client_alpns).
    """
    counts: Dict[str, int] = {}
    p = log_dir / "suricata" / "eve.json"
    if not p.exists():
        return counts
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if obj.get("event_type") != "tls":
                continue
            t = obj.get("tls", {}) or {}
            a_single = t.get("alpn")
            if isinstance(a_single, str) and a_single:
                counts[a_single] = counts.get(a_single, 0) + 1
            a_list = t.get("client_alpns")
            if isinstance(a_list, list):
                for a in a_list:
                    if isinstance(a, str) and a:
                        counts[a] = counts.get(a, 0) + 1
            elif isinstance(a_list, str) and a_list:
                counts[a_list] = counts.get(a_list, 0) + 1
    return counts


def _load_eve_tls(log_dir: Path):
    eve = []
    p = log_dir / "suricata" / "eve.json"
    if not p.exists():
        raise FileNotFoundError(f"Missing Suricata eve.json: {p}")
    with p.open() as f:
        for line in f:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if obj.get("event_type") == "tls":
                eve.append(obj)
    return eve


def summarize_tls(eve_tls) -> Tuple[Dict[str, int], Dict[str, int]]:
    ja3_counts: Dict[str, int] = {}
    alpn_counts: Dict[str, int] = {}
    for e in eve_tls:
        t = e.get("tls", {}) or {}

        # JA3 can be string or {hash: "..."}
        j = t.get("ja3")
        if isinstance(j, str) and j:
            ja3_counts[j] = ja3_counts.get(j, 0) + 1
        elif isinstance(j, dict):
            h = j.get("hash")
            if h:
                ja3_counts[h] = ja3_counts.get(h, 0) + 1

        # ALPN can be single string or list under 'client_alpns'
        a_single = t.get("alpn")
        if isinstance(a_single, str) and a_single:
            alpn_counts[a_single] = alpn_counts.get(a_single, 0) + 1

        a_list = t.get("client_alpns")
        if isinstance(a_list, list):
            for a in a_list:
                if isinstance(a, str) and a:
                    alpn_counts[a] = alpn_counts.get(a, 0) + 1
        elif isinstance(a_list, str) and a_list:
            alpn_counts[a_list] = alpn_counts.get(a_list, 0) + 1

    return ja3_counts, alpn_counts


def grade_tls_alpn_answers(log_dir: Path, answers: Dict, rubric: Dict) -> Dict:
    """
    Grade Lab 02 using ALPN distribution.
    Source priority: Zeek ssl.log (next_protocol) -> fallback to Suricata EVE tls.
    """
    alpn_counts = _alpn_counts_from_zeek_ssl(log_dir)
    source = "zeek_ssl"
    if not alpn_counts:
        alpn_counts = _alpn_counts_from_suricata(log_dir)
        source = "suricata_eve"

    total = sum(alpn_counts.values())
    if total == 0:
        return {
            "score": 0,
            "passed": False,
            "details": {
                "reason": "no_alpn_observed",
                "source": source,
                "hint": "Ensure Zeek wrote logs/zeek/ssl.log (or Suricata produced tls events).",
                "alpn_counts": alpn_counts,
            },
        }

    threshold = float(rubric["checks"]["alpn_min_share"])
    anomalies = sorted([k for k, v in alpn_counts.items() if (v / total) < threshold])
    student = sorted(list(set(answers.get("anomalous_alpn", []))))
    ok = student == anomalies
    return {
        "score": 100 if ok else 0,
        "passed": ok,
        "details": {
            "source": source,
            "alpn_counts": alpn_counts,
            "threshold": threshold,
            "expected_anomalies": anomalies,
            "student": student,
        },
    }
