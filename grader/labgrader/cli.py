import argparse
import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from .io import load_conn_log
from .checks import grade_beacon_answers, grade_tls_alpn_answers, grade_dns_exfil


def _load_yaml(p: Path):
    with p.open() as f:
        return yaml.safe_load(f)


def main():
    ap = argparse.ArgumentParser(description="Lab autograder")
    ap.add_argument(
        "lab_path",
        help="Path to lab folder, e.g., labs/01_beacon or labs/02_tls13_fingerprints",
    )
    ap.add_argument("answers_file", help="answers.yml from student")
    ap.add_argument(
        "--logs",
        required=True,
        help="Path to logs/ directory containing zeek/ and/or suricata/",
    )
    ap.add_argument(
        "--json-out",
        default="results.json",
        help="Path to write machine-readable results",
    )
    args = ap.parse_args()

    lab = Path(args.lab_path)
    answers = _load_yaml(Path(args.answers_file))
    schema = json.loads(Path(lab / "answer_schema.json").read_text())
    Draft202012Validator(schema).validate(answers)

    lab_name = lab.name
    logs_dir = Path(args.logs)

    if lab_name == "01_beacon":
        conn_rows = load_conn_log(logs_dir)
        rubric = yaml.safe_load((lab / "rubric.yml").read_text())
        res = grade_beacon_answers(conn_rows, answers, rubric)

    elif lab_name == "02_tls13_fingerprints":
        rubric = yaml.safe_load((lab / "rubric.yml").read_text())
        res = grade_tls_alpn_answers(logs_dir, answers, rubric)

    elif lab_name == "03_dns_exfil":
        rubric = yaml.safe_load((lab / "rubric.yml").read_text())
        res = grade_dns_exfil(logs_dir, answers, rubric, lab)

    else:
        print(f"Unsupported lab: {lab_name}", file=sys.stderr)
        sys.exit(2)

    print(f"Score: {res['score']:.2f}  Passed: {res['passed']}")
    Path(args.json_out).write_text(json.dumps(res, indent=2))
    sys.exit(0 if res["passed"] else 1)
