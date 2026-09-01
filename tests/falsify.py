#!/usr/bin/env python3
"""Break each report guard on purpose and require the tests to notice.

A passing suite proves the report works only if the suite would fail when it
does not. This harness edits one line of the generator at a time, reruns the
tests, and reports a defect as SURVIVED when they still pass — meaning the
behaviour that line implements is not actually covered.

    python3 tests/falsify.py            # all defects
    python3 tests/falsify.py mask       # only those matching a name

Each edit is undone in a finally block, and the file contents are restored
from memory rather than from git, so an interrupted run cannot leave a
mutated working tree behind.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT = "roles/reporter/files/skibidi-report.py"


@dataclass
class Defect:
    name: str
    find: str
    replace: str
    # What the defect does, in the terms an operator would care about. If the
    # tests survive it, this sentence describes what nobody checks.
    consequence: str


DEFECTS = [
    Defect(
        name="mask/labels-in-clear",
        find="    keep = 2 if len(text) <= 5 else 3\n"
             "    return f\"{text[:keep]}{'*' * (len(text) - keep)}\"",
        replace="    return text",
        consequence="every relative's real name rides the weekly letter in clear text",
    ),
    Defect(
        name="counters/negative-week",
        find="    return new - old if new >= old else new",
        replace="    return new - old",
        consequence="a client counter reset turns into a negative week of traffic",
    ),
    Defect(
        name="cid/attachment-drift",
        find='            cid=f"<skibidi-{name}>",',
        replace='            cid="<skibidi-chart>",',
        consequence="every chart renders as a broken-image icon in the letter",
    ),
    Defect(
        name="escape/raw-text",
        find='{html.escape(text)}</p>\'',
        replace="{text}</p>'",
        consequence="a client label chosen maliciously becomes live HTML in the mail client",
    ),
    Defect(
        name="subject/alert-blind",
        find='    prefix = "[!] " if data.get("alerts") else ""',
        replace='    prefix = ""',
        consequence="trouble no longer reaches the subject line, so nobody opens the letter",
    ),
    Defect(
        name="charts/dangling-cid",
        find="        if png:\n            charts[name] = png",
        replace="        charts[name] = png",
        consequence="an empty week attaches nothing yet references it, or crashes the send",
    ),
    Defect(
        name="window/weekday-blind",
        find="    end -= dt.timedelta(days=(local.date().weekday() - weekday) % 7)",
        replace="    _ = weekday",
        consequence="a delayed run reports a window that ends mid-week and nobody notices",
    ),
    Defect(
        name="sanitise/labels-through",
        find="        clients.append(mask_label(client.get(\"email\")))",
        replace="        clients.append(str(client.get(\"email\")))",
        consequence="the weekly snapshot in /var/lib carries every client's real name",
    ),
    Defect(
        name="diff/enable-blind",
        find='        if was["enable"] != now["enable"]:',
        replace="        if False:",
        consequence="an inbound switched off by mistake never appears in what-changed",
    ),
    Defect(
        name="alerts/silent-absence",
        find='    for name, reason in data.get("unreachable", []):',
        replace="    for name, reason in []:",
        consequence="a node that did not answer reads as a healthy, quiet node",
    ),
]


def run_suite() -> bool:
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"],
        cwd=ROOT, capture_output=True, text=True,
    )
    return result.returncode == 0


def main() -> int:
    needle = sys.argv[1] if len(sys.argv) > 1 else ""
    path = ROOT / REPORT
    original = path.read_text()

    if not run_suite():
        print("the suite is already red; falsification proves nothing here", file=sys.stderr)
        return 2

    survived = []
    for defect in DEFECTS:
        if needle and needle not in defect.name:
            continue
        if original.count(defect.find) != 1:
            print(f"stale     {defect.name}: its find-pattern no longer matches exactly once")
            survived.append(defect)
            continue
        try:
            path.write_text(original.replace(defect.find, defect.replace))
            if run_suite():
                print(f"SURVIVED  {defect.name}: {defect.consequence}")
                survived.append(defect)
            else:
                print(f"caught    {defect.name}")
        finally:
            path.write_text(original)

    if survived:
        print(f"\n{len(survived)} defect(s) survived the tests.", file=sys.stderr)
        return 1
    print(f"\nall {len([d for d in DEFECTS if not needle or needle in d.name])} "
          "defects were caught by the tests.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
