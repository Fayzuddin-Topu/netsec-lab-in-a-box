import argparse
import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from .io import load_conn_log
from .checks import grade_beacon_answers


def _load_yaml(p: Path):
    with p.open() as f:
        return yaml.safe_load(f)


def main():
    ap = argparse.ArgumentParser(description="Lab autograder")
    ap.add_argument("lab_path", help="Path to lab folder, e.g., labs/01_beacon")
    ap.add_argument("answers_file", help="answers.yml from student")
    ap.add_argument(
        "--logs", required=True, help="Path to logs/ directory containing zeek/"
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

    # Only Lab 01 implemented in v1
    rubric = yaml.safe_load((lab / "rubric.yml").read_text())
    conn_rows = load_conn_log(Path(args.logs))
    res = grade_beacon_answers(conn_rows, answers, rubric)

    # Pretty print
    print(f"Score: {res['score']:.2f}  Passed: {res['passed']}")
    for d in res["details"]:
        status = "OK" if d["ok"] else "FAIL"
        print(
            f"- {d['endpoint']}: {status} (period {d['period']['answer']} vs {d['period']['ref']}, count {d['count']['answer']} vs {d['count']['ref']})"
        )

    Path(args.json_out).write_text(json.dumps(res, indent=2))
    sys.exit(0 if res["passed"] else 1)
