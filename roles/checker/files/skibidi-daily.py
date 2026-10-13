#!/usr/bin/env python3
"""List everything on this node that is still open. Exit 1 when there is any.

The second level of the two. `skibidi-check` fails within half an hour for
what must work now and mails at once. This runs once a day and puts into one
mail every item still open, urgent or not, and it mails nothing when nothing
is open. It does that by failing its own unit when it lists anything: the
alert unit that mails a failed `skibidi-check` mails this one the same way,
with the journal of the run, and its last line is the subject.

An item that stays open comes again the next day, because this keeps no state
between runs. Where an item is defined:

- the urgent ones: the last run of `skibidi-check`, which leaves its failures
  in a file;
- the rest: the rules in skibidi_problems.py, read from the numbers this
  node's metrics API serves, and on the master from `skibidi-report problems`.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, os.environ.get("SKIBIDI_LIB", "/usr/local/lib/skibidi"))
import skibidi_problems  # noqa: E402
import skibidi_push  # noqa: E402


REQUIRED = ("SKIBIDI_CHECK_RESULT", "SKIBIDI_CHECK_MAX_AGE_HOURS", "SKIBIDI_API_URL")


def get(base: str, path: str, query: dict | None = None):
    url = base.rstrip("/") + path + ("?" + urllib.parse.urlencode(query) if query else "")
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.loads(response.read())


def node_problems(environ, now: float) -> list[str]:
    base = environ["SKIBIDI_API_URL"]
    window = skibidi_push.LATEST_WINDOW_SECONDS
    try:
        health = get(base, "/v1/health")
        answer = get(base, "/v1/samples", {"from": int(now) - window, "to": int(now) + 60})
    except urllib.error.HTTPError as error:
        return [f"the metrics API of this node answered HTTP {error.code}: {error.reason}"]
    except (urllib.error.URLError, OSError, ValueError) as error:
        return [f"the metrics API of this node did not answer: {getattr(error, 'reason', error)}"]
    # Rows come oldest first, so a cut answer lacks exactly the newest ones
    if answer.get("truncated"):
        return ["the metrics API of this node cut its answer, so the newest samples are missing"]
    rows = [
        (row["ts_us"], row["metric"], next(iter(row["dimensions"].values()), ""), row["value"])
        for row in answer["rows"]
    ]
    latest = {key: value for key, (_ts, value) in skibidi_push.latest(rows).items()}
    return skibidi_problems.node_problems(latest, health, now)


def panel_problems(environ) -> list[str]:
    command = environ.get("SKIBIDI_REPORT_BIN", "")
    if not command or not Path(command).exists():
        return []
    try:
        done = subprocess.run([command, "problems"], capture_output=True, text=True,
                              timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        return [f"the panel could not be asked: {error}"]
    if done.returncode != 0:
        return [f"the panel could not be asked: skibidi-report problems exited {done.returncode}"]
    return [line for line in done.stdout.splitlines() if line.strip()]


def main(argv: list[str], environ=os.environ) -> int:
    if argv:
        print("usage: skibidi-daily", file=sys.stderr)
        return 2
    # Exit 1 is the answer "something is open", and a traceback exits with 1
    # too, so a run without its settings has to leave by another code
    missing = [key for key in REQUIRED if key not in environ]
    if missing:
        print(f"skibidi-daily: {', '.join(missing)} not set; run it with the environment "
              "of skibidi-daily.service, which systemd-run --property=EnvironmentFile= gives it",
              file=sys.stderr)
        return 2
    host = socket.gethostname()
    found = skibidi_problems.check_failures(
        environ["SKIBIDI_CHECK_RESULT"], float(environ["SKIBIDI_CHECK_MAX_AGE_HOURS"])
    ) + node_problems(environ, time.time()) + panel_problems(environ)
    if not found:
        print(f"nothing is open on {host}")
        return 0
    # FAIL is what the alert mail marks as the line that says what broke
    for item in found:
        print(f"FAIL {item}")
    print(f"{len(found)} unresolved item(s) on {host}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
