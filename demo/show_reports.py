from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.config import Config


def main() -> None:
    parser = argparse.ArgumentParser(description="Print Linz demo incident reports.")
    parser.add_argument("--latest", action="store_true", help="Only print the latest report.")
    args = parser.parse_args()

    config = Config.from_env()
    report_path = config.demo_dir / "linz_reports.jsonl"
    if not report_path.exists():
        raise SystemExit("No reports found. Run `python3 demo/run_demo.py --scenario ssh_bruteforce` first.")

    reports = [json.loads(line)["event"] for line in report_path.read_text().splitlines() if line.strip()]
    if args.latest:
        reports = reports[-1:]

    for report in reports:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
