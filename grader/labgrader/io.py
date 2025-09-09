from pathlib import Path
from typing import List, Dict, Tuple


def parse_zeek_tsv(path: Path) -> Tuple[List[str], List[List[str]]]:
    if not path.exists():
        raise FileNotFoundError(f"Missing Zeek log: {path}")
    fields = None
    rows: List[List[str]] = []
    with path.open() as f:
        for line in f:
            if line.startswith("#fields"):
                parts = line.rstrip("\n").split("\t")
                fields = parts[1:]
            elif line.startswith("#") or not line.strip():
                continue
            else:
                rows.append(line.rstrip("\n").split("\t"))
    if fields is None:
        raise ValueError(f"No #fields header found in {path}")
    return fields, rows


def load_conn_log(log_dir: Path):
    fields, rows = parse_zeek_tsv(log_dir / "zeek" / "conn.log")
    idx = {name: i for i, name in enumerate(fields)}
    out: List[Dict] = []
    for r in rows:
        d: Dict = {name: r[i] for name, i in idx.items()}
        try:
            d["ts"] = float(d["ts"])
        except Exception:
            pass
        try:
            d["id.resp_p"] = int(float(d["id.resp_p"]))
        except Exception:
            pass
        out.append(d)
    return out
