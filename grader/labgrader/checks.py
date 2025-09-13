from collections import defaultdict
from statistics import mean, pstdev
from typing import Dict, List, Tuple, Optional
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


# --- Lab 03: DNS exfiltration (Zeek) -----------------------------------------


def grade_dns_exfil(
    log_dir: Path,
    answers: Dict,
    rubric: Dict,
    lab_dir: Optional[Path] = None,
) -> Dict:
    """
    Grade Lab 03 using Zeek dns.log.

    Inputs:
      - log_dir: Path to ./logs (expects logs/zeek/dns.log)
      - answers: dict loaded from answers.yml (expects 'suspect_rrnames': list[str])
      - rubric: dict loaded from labs/03_dns_exfil/rubric.yml
         checks:
           expected_suffixes: [list of domain suffixes to match]
           accept_by_suffix: true
           entropy_threshold: 3.2
           entropy_tolerance: 0.3
           label_count_min: 8
           max_label_len_min: 40
           txt_ratio_min: 0.20
           nxdomain_ratio_min: 0.50
           require_entropy_evidence: true
         grading:
           per_item_points: 50
           pass_threshold: 80
           required_count: 2
      - lab_dir: optional, used to read expected/summary.json if rubric has no expected list

    Returns:
      dict: {"score": float, "passed": bool, "details": {...}}
    """
    import math
    import re
    import json
    from collections import Counter, defaultdict

    # ---------- helpers ----------
    def _canon(name: str) -> str:
        if not name:
            return name
        s = name.strip().lower()
        return s if s.endswith(".") else s + "."

    def _entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = Counter(s)
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in freq.values() if c)

    def _suffix_match(candidate: str, expected_suffix: str) -> bool:
        c = _canon(candidate)
        e = _canon(expected_suffix)
        return c.endswith(e)

    def _collect_metrics(rows):
        per = defaultdict(
            lambda: {
                "total": 0,
                "txt": 0,
                "nx": 0,
                "len": 0,
                "labels": 0,
                "max_label": 0,
                "entropy": 0.0,
            }
        )
        for r in rows:
            qname = _canon(r.get("query", ""))
            if not qname:
                continue
            qtype = r.get("qtype_name") or r.get("qtype")
            rcode = (r.get("rcode_name") or r.get("rcode") or "").upper()
            per[qname]["total"] += 1
            if str(qtype).upper() == "TXT" or str(qtype) == "16":
                per[qname]["txt"] += 1
            if rcode == "NXDOMAIN" or rcode == "3":
                per[qname]["nx"] += 1
            labels = qname.rstrip(".").split(".")
            per[qname]["len"] = max(per[qname]["len"], len(qname))
            per[qname]["labels"] = max(per[qname]["labels"], len(labels))
            per[qname]["max_label"] = max(
                per[qname]["max_label"], max(len(lab) for lab in labels)
            )
            clean = re.sub(r"[^a-z0-9]", "", qname.lower())
            per[qname]["entropy"] = _entropy(clean)
        return per

    # ---------- load data ----------
    dns_log = log_dir / "zeek" / "dns.log"
    rows = list(_iter_zeek_tsv(dns_log))  # reuses your existing helper
    if not rows:
        return {
            "score": 0,
            "passed": False,
            "details": {
                "reason": "no_dns_rows",
                "path": str(dns_log),
            },
        }

    # rubric defaults (safe fallbacks)
    checks = {
        "expected_suffixes": [],
        "accept_by_suffix": True,
        "entropy_threshold": 3.2,
        "entropy_tolerance": 0.3,
        "max_label_len_min": 40,
        "label_count_min": 8,
        "txt_ratio_min": 0.20,
        "nxdomain_ratio_min": 0.50,
        "require_entropy_evidence": True,
        "required_count": 1,
    }
    checks.update(rubric.get("checks", {}))

    grading = {
        "per_item_points": 50,
        "pass_threshold": 80,
    }
    grading.update(rubric.get("grading", {}))

    expected = list(map(_canon, checks.get("expected_suffixes") or []))
    if not expected and lab_dir:
        # Optional fallback: labs/03_dns_exfil/expected/summary.json
        sfile = Path(lab_dir) / "expected" / "summary.json"
        if sfile.exists():
            try:
                summary = json.loads(sfile.read_text())
                exp = summary.get("expected_domains", [])
                if isinstance(exp, list):
                    expected = list(map(_canon, exp))
            except Exception:
                pass

    student = list(map(_canon, (answers or {}).get("suspect_rrnames", [])))
    if not student:
        return {
            "score": 0,
            "passed": False,
            "details": {"reason": "answers_missing_suspect_rrnames"},
        }

    per = _collect_metrics(rows)

    # Entropy/shape evidence gate: at least one student item should look exfil-like
    ent_thresh = checks["entropy_threshold"] - checks["entropy_tolerance"]

    def _looks_exfil(m):
        total = max(1, int(m["total"]))
        return (
            m["max_label"] >= checks["max_label_len_min"]
            or m["labels"] >= checks["label_count_min"]
            or (m["txt"] / total) >= checks["txt_ratio_min"]
            or (m["nx"] / total) >= checks["nxdomain_ratio_min"]
            or m["entropy"] >= ent_thresh
        )

    ent_ok = False
    for s in student:
        m = per.get(_canon(s))
        if not m:
            # suffix match to metrics, if student gave a subdomain
            hits = [k for k in per.keys() if _suffix_match(k, s)]
            if hits:
                m = per[hits[0]]
        if m and _looks_exfil(m):
            ent_ok = True
            break

    # name matching against expected suffixes
    correct = 0
    missing = []
    if expected:
        for exp in expected:
            if any(_suffix_match(s, exp) for s in student):
                correct += 1
            else:
                missing.append(exp)

    # score & pass
    score = grading["per_item_points"] * correct
    required_count = int(checks.get("required_count", 1))
    pass_by_count = correct >= required_count
    pass_by_score = score >= grading["pass_threshold"]
    passed = (pass_by_count or pass_by_score) and (
        (not checks["require_entropy_evidence"]) or ent_ok
    )

    # small preview of grader-suspects for hints
    grader_suspects = []
    for name, m in per.items():
        if _looks_exfil(m):
            grader_suspects.append((name, m["entropy"], m["max_label"]))
    grader_suspects.sort(key=lambda x: (-x[1], -x[2]))
    grader_suspects = [g[0] for g in grader_suspects[:6]]

    return {
        "score": float(score),
        "passed": bool(passed),
        "details": {
            "student_count": len(student),
            "expected_suffixes": expected,
            "missing_expected": missing,
            "entropy_condition_met": ent_ok,
            "examples": grader_suspects,
        },
    }
