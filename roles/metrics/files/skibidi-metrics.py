#!/usr/bin/env python3
"""Sample the OS-level state the weekly report is built from.

One row per metric per run, appended to SQLite. The report generator on the
master pulls a window of rows over SSH through a forced-command key, so this
script is also its own SSH gate: the key installed for the master may run
nothing but `export`, with arguments this file validates.

Counters that other software owns (fail2ban totals, unit restart counts) are
stored as the cumulative values they are; turning them into deltas is the
reader's job, because only the reader knows the window it is asking about.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

DB_PATH = Path(os.environ.get("SKIBIDI_METRICS_DB", "/var/lib/skibidi-metrics/metrics.db"))
RETENTION_DAYS = int(os.environ.get("SKIBIDI_METRICS_RETENTION_DAYS", "90"))
WATCHED_TIMERS = os.environ.get(
    "SKIBIDI_WATCHED_TIMERS",
    "skibidi-check.timer xray-geodata-update.timer skibidi-metrics.timer",
).split()
WATCHED_UNITS = os.environ.get(
    "SKIBIDI_WATCHED_UNITS", "x-ui nginx fail2ban tailscaled"
).split()

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    ts_us INTEGER NOT NULL,
    metric TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    value REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS samples_ts ON samples (ts_us);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def connect() -> sqlite3.Connection:
    # 0640/0750 rather than 0600/0700: the export runs as an unprivileged
    # account that reaches the store through group read, set up by the role.
    # Root stays the only writer
    DB_PATH.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.executescript(SCHEMA)
    os.chmod(DB_PATH, 0o640)
    return connection


def connect_readonly() -> sqlite3.Connection:
    # mode=ro never creates the file and refuses every write below SQL level,
    # so a bug in the export path cannot damage what the collector wrote — and
    # unlike a plain open it needs no journal files created beside the store,
    # which the export account could not create anyway
    connection = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=30)
    connection.execute("PRAGMA query_only = ON")
    return connection


def run(*argv: str) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{argv[0]}: {result.stderr.strip() or result.returncode}")
    return result.stdout


def read_first(path: str) -> str:
    return Path(path).read_text().split("\n", 1)[0]


# ---------------------------------------------------------------- probes
#
# Each probe returns (metric, detail, value) tuples. A probe that fails costs
# its own rows and a line in the journal, never the run: the report says which
# numbers are missing, which beats a node that stopped reporting entirely.


def probe_load():
    yield "load1", "", float(read_first("/proc/loadavg").split()[0])


def probe_memory():
    fields = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, _, rest = line.partition(":")
        fields[key] = int(rest.split()[0])
    total = fields["MemTotal"]
    yield "mem_used_ratio", "", 1 - fields["MemAvailable"] / total


def probe_disk():
    stat = os.statvfs("/")
    total = stat.f_blocks * stat.f_frsize
    yield "disk_used_ratio", "", 1 - stat.f_bavail / stat.f_blocks
    yield "disk_total_bytes", "", float(total)


def probe_uptime():
    yield "uptime_seconds", "", float(read_first("/proc/uptime").split()[0])


def probe_conntrack():
    base = "/proc/sys/net/netfilter"
    count = int(read_first(f"{base}/nf_conntrack_count"))
    maximum = int(read_first(f"{base}/nf_conntrack_max"))
    yield "conntrack_used_ratio", "", count / maximum if maximum else 0.0
    yield "conntrack_count", "", float(count)


def probe_stuck_sockets():
    # The symptom of the timeout bug: ESTABLISHED sockets with no timer armed
    # accumulate until the port stops answering, and nothing logs on the way
    out = run("ss", "-H", "-t", "-n", "-o", "state", "established")
    lines = [line for line in out.splitlines() if line.strip()]
    stuck = sum(1 for line in lines if "timer:" not in line)
    yield "established_sockets", "", float(len(lines))
    yield "established_no_timer", "", float(stuck)


def probe_fail2ban():
    jails_line = run("fail2ban-client", "status")
    match = re.search(r"Jail list:\s*(.*)", jails_line)
    jails = [j.strip() for j in (match.group(1) if match else "").split(",") if j.strip()]
    for jail in jails:
        status = run("fail2ban-client", "status", jail)
        for label, metric in (
            ("Total failed", "f2b_failed_total"),
            ("Total banned", "f2b_banned_total"),
            ("Currently banned", "f2b_banned_now"),
        ):
            found = re.search(rf"{label}:\s*(\d+)", status)
            if found:
                yield metric, jail, float(found.group(1))


def probe_updates():
    # -s upgrade rather than the update-notifier file: the file only exists
    # where update-notifier-common happens to be installed
    out = run("apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade")
    yield "pkg_updates", "", float(sum(1 for line in out.splitlines() if line.startswith("Inst ")))
    yield "reboot_required", "", float(Path("/var/run/reboot-required").exists())


def probe_unit_restarts():
    for unit in WATCHED_UNITS:
        try:
            value = run("systemctl", "show", "-p", "NRestarts", "--value", unit).strip()
        except RuntimeError:
            continue
        if value.isdigit():
            yield "unit_restarts", unit, float(value)


def probe_timers():
    for timer in WATCHED_TIMERS:
        try:
            value = run("systemctl", "show", "-p", "LastTriggerUSec", "--value", timer).strip()
        except RuntimeError:
            continue
        if value and value != "n/a":
            try:
                epoch = float(run("date", "-d", value, "+%s").strip())
            except (RuntimeError, ValueError):
                continue
            yield "timer_last_fired", timer, epoch


def probe_ufw_drops(connection: sqlite3.Connection, now_us: int):
    # A count over the interval since the last run, cut by the same clock the
    # store keeps, so two runs never count the same drop twice
    row = connection.execute(
        "SELECT value FROM state WHERE key = 'collected_through_us'"
    ).fetchone()
    since_us = int(row[0]) if row else now_us - 600 * 1_000_000
    out = run(
        "journalctl", "-k", "-o", "cat", "-q",
        "--since", f"@{since_us // 1_000_000}",
        "--until", f"@{now_us // 1_000_000}",
    )
    yield "ufw_drops", "", float(sum(1 for line in out.splitlines() if "[UFW BLOCK]" in line))


PROBES = [
    probe_load,
    probe_memory,
    probe_disk,
    probe_uptime,
    probe_conntrack,
    probe_stuck_sockets,
    probe_fail2ban,
    probe_updates,
    probe_unit_restarts,
    probe_timers,
]


def collect() -> int:
    now_us = int(time.time() * 1_000_000)
    failed = []
    with connect() as connection:
        rows = []
        # A lambda has a __name__ too, "<lambda>", so the journal line names
        # the probe explicitly rather than trusting the attribute
        drops = lambda: probe_ufw_drops(connection, now_us)  # noqa: E731
        for probe in PROBES + [drops]:
            name = "probe_ufw_drops" if probe is drops else probe.__name__
            try:
                rows.extend((now_us, m, d, v) for m, d, v in probe())
            except Exception as error:  # noqa: BLE001 — one probe must not cost the run
                failed.append(name)
                print(f"{name}: {error}", file=sys.stderr)
        connection.executemany(
            "INSERT INTO samples (ts_us, metric, detail, value) VALUES (?, ?, ?, ?)", rows
        )
        connection.execute(
            "DELETE FROM samples WHERE ts_us < ?",
            (now_us - RETENTION_DAYS * 86400 * 1_000_000,),
        )
        # Advanced even when probes failed: freshness means the collector ran,
        # and which metrics are missing is the report's question to answer
        connection.execute(
            "INSERT INTO state (key, value) VALUES ('collected_through_us', ?) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (str(now_us),),
        )
    return 0


def export(since_us: int, until_us: int) -> int:
    with connect_readonly() as connection:
        samples = connection.execute(
            "SELECT ts_us, metric, detail, value FROM samples "
            "WHERE ts_us >= ? AND ts_us < ? ORDER BY ts_us",
            (since_us, until_us),
        ).fetchall()
        row = connection.execute(
            "SELECT value FROM state WHERE key = 'collected_through_us'"
        ).fetchone()
    json.dump(
        {
            "node": socket.gethostname(),
            "now_us": int(time.time() * 1_000_000),
            "collected_through_us": int(row[0]) if row else 0,
            "samples": samples,
        },
        sys.stdout,
        separators=(",", ":"),
    )
    print()
    return 0


EXPORT_SHAPE = re.compile(r"^skibidi-metrics export --since (\d{1,20}) --until (\d{1,20})$")


def ssh_guard() -> int:
    """The only door the master's key opens.

    authorized_keys forces this entry point, so whatever the client asked for
    arrives as text here and either matches the one permitted shape or is
    refused. The alternative — trusting the client's command line — would turn
    a metrics key into a root shell.
    """
    original = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    match = EXPORT_SHAPE.match(" ".join(shlex.split(original)))
    if not match:
        print("this key exports metrics and does nothing else", file=sys.stderr)
        return 2
    return export(int(match.group(1)), int(match.group(2)))


def main(argv: list[str]) -> int:
    if len(argv) >= 1 and argv[0] == "collect":
        return collect()
    if len(argv) >= 1 and argv[0] == "ssh-guard":
        return ssh_guard()
    if (
        len(argv) == 5
        and argv[0] == "export"
        and argv[1] == "--since"
        and argv[3] == "--until"
        and argv[2].isdigit()
        and argv[4].isdigit()
    ):
        return export(int(argv[2]), int(argv[4]))
    print("usage: skibidi-metrics collect | export --since US --until US", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
