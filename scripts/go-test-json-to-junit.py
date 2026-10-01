#!/usr/bin/env python3
"""Convert the JSON stream emitted by `go test -json` to JUnit XML."""

from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from collections import OrderedDict
from pathlib import Path


def main() -> int:
    if len(sys.argv) not in (3, 4):
        print(
            f"usage: {sys.argv[0]} INPUT.jsonl OUTPUT.xml [SUMMARY.md]",
            file=sys.stderr,
        )
        return 2

    input_path, output_path = map(Path, sys.argv[1:3])
    summary_path = Path(sys.argv[3]) if len(sys.argv) == 4 else None
    suites: OrderedDict[str, dict] = OrderedDict()

    if input_path.exists():
        for line in input_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            package = str(event.get("Package") or "unknown")
            suite = suites.setdefault(
                package,
                {"status": None, "elapsed": 0.0, "logs": [], "tests": OrderedDict()},
            )
            test_name = event.get("Test")
            action = event.get("Action")
            if test_name:
                test = suite["tests"].setdefault(
                    str(test_name), {"status": None, "elapsed": 0.0, "logs": []}
                )
                if action == "output":
                    test["logs"].append(str(event.get("Output") or ""))
                elif action in {"pass", "fail", "skip"}:
                    test["status"] = action
                    test["elapsed"] = float(event.get("Elapsed") or 0.0)
            elif action == "output":
                suite["logs"].append(str(event.get("Output") or ""))
            elif action in {"pass", "fail", "skip"}:
                suite["status"] = action
                suite["elapsed"] = float(event.get("Elapsed") or 0.0)

    root = ET.Element("testsuites")
    total = failures = skipped = errors = 0
    for package, suite in suites.items():
        tests = suite["tests"]
        if not tests and suite["status"] == "fail":
            tests["package"] = {
                "status": "error",
                "elapsed": suite["elapsed"],
                "logs": suite["logs"],
            }

        suite_failures = sum(test["status"] == "fail" for test in tests.values())
        suite_skipped = sum(test["status"] == "skip" for test in tests.values())
        suite_errors = sum(test["status"] == "error" for test in tests.values())
        suite_element = ET.SubElement(
            root,
            "testsuite",
            {
                "name": package,
                "tests": str(len(tests)),
                "failures": str(suite_failures),
                "errors": str(suite_errors),
                "skipped": str(suite_skipped),
                "time": f"{suite['elapsed']:.3f}",
            },
        )
        for name, test in tests.items():
            total += 1
            testcase = ET.SubElement(
                suite_element,
                "testcase",
                {"name": name, "classname": package, "time": f"{test['elapsed']:.3f}"},
            )
            status = test["status"]
            logs = "".join(test["logs"])
            if status == "fail":
                failures += 1
                failure = ET.SubElement(testcase, "failure", {"message": "test failed"})
                failure.text = logs
            elif status == "error":
                errors += 1
                error = ET.SubElement(testcase, "error", {"message": "package failed"})
                error.text = logs
            elif status == "skip":
                skipped += 1
                ET.SubElement(testcase, "skipped")
            elif logs:
                output = ET.SubElement(testcase, "system-out")
                output.text = logs

    ET.indent(root, space="  ")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(output_path, encoding="utf-8", xml_declaration=True)

    if summary_path:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(
            "\n".join(
                [
                    "### Test results",
                    "",
                    f"- Tests: {total}",
                    f"- Failures: {failures}",
                    f"- Errors: {errors}",
                    f"- Skipped: {skipped}",
                    "",
                ]
            ),
            encoding="utf-8",
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
