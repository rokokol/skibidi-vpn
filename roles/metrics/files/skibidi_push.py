"""What the collector, the reporter and the daily check share about the station.

A node pushes its numbers to the Prometheus Pushgateway of the station that
receives its backups. The station is named once, by `backup_url` in the node
file, and the account is the backup account: the role turns both into the
environment this module reads. The contract with the station is in
docs/metrics-api.md, "The push".
"""

from __future__ import annotations

import base64
import re
import shlex
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

JOB = "vpn"
PREFIX = "vpn_"
# The one name outside the prefix. The station's own rule for a node that
# reports trouble with itself reads exactly this, in the node's own group
UNPREFIXED = frozenset({"node_problem"})

# A series counts as current while its newest sample is this young. It is
# longer than the hourly updates probe, and short enough that a probe which
# stopped answering drops out instead of looking alive. The push and the daily
# check read the same window
LATEST_WINDOW_SECONDS = 2 * 3600

NAME = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
LABEL_NAME = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


class PushError(Exception):
    """A push that did not happen. The text may reach a journal, so it never
    holds the password."""


def latest(rows):
    """The newest (timestamp, value) of every series in (ts, metric, detail, value) rows."""
    newest: dict = {}
    for ts, metric, detail, value in rows:
        key = (metric, detail)
        if key not in newest or ts >= newest[key][0]:
            newest[key] = (ts, value)
    return newest


def family(name: str, kind: str, help_text: str, samples) -> dict:
    return {"name": name, "type": kind, "help": help_text, "samples": list(samples)}


def escape_label(value) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render(families) -> str:
    """The text exposition format. A name outside the prefix, a bad label name
    and a repeated label set are refused here, because the station refuses the
    whole body for any of them and the push would never arrive"""
    lines = []
    for item in families:
        name = item["name"]
        if not NAME.match(name) or not (name.startswith(PREFIX) or name in UNPREFIXED):
            raise ValueError(f"{name!r} is not a {PREFIX} metric name")
        seen = set()
        lines.append(f"# HELP {name} {item['help'].replace(chr(10), ' ')}")
        lines.append(f"# TYPE {name} {item['type']}")
        for labels, value in sorted(item["samples"], key=lambda pair: sorted(pair[0].items())):
            for label in labels:
                if not LABEL_NAME.match(label):
                    raise ValueError(f"{label!r} is not a label name")
            key = tuple(sorted(labels.items()))
            if key in seen:
                raise ValueError(f"{name} repeats the label set {dict(key)}")
            seen.add(key)
            text = ",".join(f'{label}="{escape_label(labels[label])}"' for label in sorted(labels))
            lines.append(f"{name}{{{text}}} {float(value)!r}" if text else f"{name} {float(value)!r}")
    return "\n".join(lines) + "\n"


def target(environ):
    """The station to push to, or None where the node names no station.

    SKIBIDI_PUSH_BASE is the station's address with the Pushgateway's port,
    SKIBIDI_PUSH_USER the backup account, which is also the instance label,
    SKIBIDI_PUSH_PASSWORD_FILE the root-only file that holds its password and
    SKIBIDI_PUSH_GUARD the command that refuses a station the backup refuses.
    """
    base = environ.get("SKIBIDI_PUSH_BASE", "")
    if not base:
        return None
    user = environ.get("SKIBIDI_PUSH_USER", "")
    source = environ.get("SKIBIDI_PUSH_PASSWORD_FILE", "")
    if not user or not source:
        raise PushError("SKIBIDI_PUSH_BASE is set without SKIBIDI_PUSH_USER and SKIBIDI_PUSH_PASSWORD_FILE")
    guard = shlex.split(environ.get("SKIBIDI_PUSH_GUARD", "")) or None
    return {"base": base.rstrip("/"), "user": user, "password_file": source, "guard": guard}


def push_text(station: dict, body: str, timeout: float = 15) -> None:
    if station["guard"]:
        try:
            checked = subprocess.run(station["guard"], capture_output=True, text=True,
                                     timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise PushError(f"the station could not be checked: {error}") from None
        if checked.returncode != 0:
            raise PushError(f"the station is refused: {(checked.stderr or checked.stdout).strip()}")
    try:
        phrase = Path(station["password_file"]).read_text()
    except OSError as error:
        raise PushError(f"cannot read the password file: {error.strerror or error}") from None
    user = station["user"]
    login = base64.b64encode(f"{user}:{phrase}".encode()).decode()
    url = f"{station['base']}/metrics/job/{JOB}/instance/{urllib.parse.quote(user, safe='')}"
    # PUT replaces the whole group. This host's collector is the only writer
    # of its group, so a problem or a series that went away is missing from
    # the next body and goes from the station with it. POST would leave it there
    request = urllib.request.Request(url, data=body.encode(), method="PUT", headers={
        "Authorization": f"Basic {login}",
        "Content-Type": "text/plain; version=0.0.4",
    })
    try:
        with urllib.request.urlopen(request, timeout=timeout):
            return
    except urllib.error.HTTPError as error:
        with error:
            raise PushError(f"the station answered HTTP {error.code}") from None
    except (urllib.error.URLError, OSError) as error:
        raise PushError(f"the station did not answer: {getattr(error, 'reason', error)}") from None


def push(station: dict, families, timeout: float = 15) -> None:
    push_text(station, render(families), timeout)


SAMPLE = re.compile(r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>.*)\})? [-+]?(?:[0-9.]+(?:[eE][-+]?[0-9]+)?|Inf|NaN)$")


def validate_text(text: str, taken=()) -> set:
    """The family names of a text exposition another program wrote, or a
    ValueError for the first thing the station would refuse. The station
    refuses a whole body for one bad line, and the body is this node's sign of
    life, so a file is read here before it may join one. Names the body already
    holds, and the one unprefixed name, are not the file's to write"""
    if not text.endswith("\n"):
        raise ValueError("the text does not end with a newline")
    names, seen = set(), set()
    for number, line in enumerate(text.split("\n")[:-1], 1):
        if not line or line.startswith("# HELP ") or line.startswith("# TYPE "):
            if line.startswith(("# HELP ", "# TYPE ")):
                names.add(line.split(" ")[2])
            continue
        found = SAMPLE.match(line)
        if not found:
            raise ValueError(f"line {number} is not a sample")
        names.add(found["name"])
        if (found["name"], found["labels"]) in seen:
            raise ValueError(f"line {number} repeats a label set")
        seen.add((found["name"], found["labels"]))
    for name in names:
        if not name.startswith(PREFIX) or name in taken:
            raise ValueError(f"{name} is not the file's to write")
    return names
