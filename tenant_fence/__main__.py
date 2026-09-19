import argparse
import json
import sys
from pathlib import Path

from .core import InvalidExperiment, evaluate
from .demo import run
from .report import write_report


def main():
    parser = argparse.ArgumentParser(
        description="Synthetic, read-only tenant boundary checks on loopback HTTP."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo")
    demo.add_argument("--out", default="artifacts")
    check = commands.add_parser("check")
    check.add_argument("--base-url", required=True)
    check.add_argument("--manifest", required=True)
    check.add_argument("--out", default="artifacts")
    args = parser.parse_args()
    try:
        if args.command == "demo":
            results = run()
        else:
            with Path(args.manifest).open("rb") as source:
                raw = source.read(65537)
            if len(raw) > 65536:
                raise InvalidExperiment("Manifest too large")
            results = [evaluate(args.base_url, json.loads(raw))]
        write_report(
            args.out, "tenant-fence", "A tenant ID is not authorization.", results
        )
        print(json.dumps({"verdicts": [r["verdict"] for r in results]}))
        if args.command == "demo":
            return (
                0
                if [r["verdict"] for r in results]
                == ["FAIL", "FAIL", "FAIL", "PASS", "INCONCLUSIVE"]
                else 2
            )
        return {"PASS": 0, "FAIL": 1, "INCONCLUSIVE": 2}[results[0]["verdict"]]
    except (InvalidExperiment, OSError, ValueError, RecursionError):
        try:
            write_report(
                args.out,
                "tenant-fence",
                "Experiment incomplete.",
                [
                    {
                        "experiment": "input or execution error",
                        "verdict": "INCONCLUSIVE",
                        "summary": "The experiment did not complete. No security conclusion is available.",
                    }
                ],
            )
        except OSError:
            pass
        print(
            "Experiment could not be completed; check the manifest, loopback origin and token environment.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
