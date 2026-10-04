#!/usr/bin/env python3
"""Sample the OS-level state the weekly report is built from, and serve it.

`collect` appends one row per metric per run to SQLite, as root, from a timer.
`serve` answers one HTTP request on the connection systemd hands it on fd 0,
as an unprivileged dynamic user that can only read the store. The API is
described in docs/metrics-api.md; the weekly letter and any dashboard read the
fleet through it, over the tailnet.

Counters that other software owns (fail2ban totals, unit restart counts) are
stored as the cumulative values they are. Turning them into deltas is done at
read time, because only the reader knows the window it is asking about.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

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
    # 0640/0750 rather than 0600/0700: the API runs as an unprivileged user
    # that reaches the store through group read, set up by the role. Root
    # stays the only writer
    DB_PATH.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.executescript(SCHEMA)
    os.chmod(DB_PATH, 0o640)
    return connection


def readonly_connection(path=None):
    # mode=ro never creates the file and refuses every write below SQL level,
    # so a bug in the API cannot damage what the collector wrote. It also
    # needs no journal files created beside the store, which the API user
    # could not create anyway. closing(), because sqlite3's own context
    # manager commits on exit and never closes
    connection = sqlite3.connect(f"file:{path or DB_PATH}?mode=ro", uri=True, timeout=5)
    connection.execute("PRAGMA query_only = ON")
    return contextlib.closing(connection)


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

# Metrics stored as the cumulative totals their owner keeps. The API turns
# these into deltas; every other metric is a gauge, read as it was sampled
COUNTERS = frozenset({"f2b_failed_total", "f2b_banned_total", "unit_restarts"})

# What a probe's detail column means, so the API can name it. A detail on a
# metric missing here is still served, under the generic name "detail"
DIMENSIONS = {
    "f2b_failed_total": "jail",
    "f2b_banned_total": "jail",
    "f2b_banned_now": "jail",
    "unit_restarts": "unit",
    "timer_last_fired": "timer",
}


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


UPDATES_INTERVAL_US = int(os.environ.get("SKIBIDI_UPDATES_INTERVAL", "3600")) * 1_000_000


def probe_updates(connection: sqlite3.Connection, now_us: int):
    # -s upgrade rather than the update-notifier file: the file only exists
    # where update-notifier-common happens to be installed. Once an hour, not
    # every run: a package index changes daily at most, the simulation costs
    # seconds of CPU, and the report reads the last value either way
    row = connection.execute(
        "SELECT value FROM state WHERE key = 'updates_checked_us'"
    ).fetchone()
    if row and now_us - int(row[0]) < UPDATES_INTERVAL_US:
        return
    out = run("apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade")
    connection.execute(
        "INSERT INTO state (key, value) VALUES ('updates_checked_us', ?) "
        "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (str(now_us),),
    )
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
    probe_unit_restarts,
    probe_timers,
]


def collect() -> int:
    now_us = int(time.time() * 1_000_000)
    failed = []
    with connect() as connection:
        rows = []
        # The probes that need the store's clock and state are bound here;
        # named explicitly, because a lambda's __name__ is "<lambda>"
        bound = [
            ("probe_updates", lambda: probe_updates(connection, now_us)),
            ("probe_ufw_drops", lambda: probe_ufw_drops(connection, now_us)),
        ]
        for name, probe in [(p.__name__, p) for p in PROBES] + bound:
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


# ---------------------------------------------------------------- the API
#
# Paths, parameters, shapes and status codes follow the mail host's mail-stats
# API, so one dashboard can read both. docs/metrics-api.md is the contract

RESOLUTIONS = {"hour": 3600, "day": 86400}
# A month of raw rows is about 120 000; a longer view is what /v1/aggregates
# is for
SAMPLES_MAX_DAYS = 31
SAMPLES_LIMIT = 200_000
AGGREGATES_LIMIT = 10_000


def now_seconds() -> int:
    return int(time.time())


def clamped_delta(new: float, old: float) -> float:
    # A counter that went down was reset; the honest step is everything the
    # new counter has seen, not a negative one. The reporter applies the same
    # rule to its raw rows
    return new - old if new >= old else new


def dimensions(metric: str, detail: str) -> dict:
    return {DIMENSIONS.get(metric, "detail"): detail} if detail else {}


def parse_timestamp(value, default):
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as error:
        raise ValueError("timestamps must be Unix seconds") from error


def window_query(query, maximum_days):
    now = now_seconds()
    start = parse_timestamp(query.get("from", [None])[0], now - 86400)
    end = parse_timestamp(query.get("to", [None])[0], now)
    if start >= end or end - start > maximum_days * 86400:
        raise ValueError(
            f"the requested range must be positive and at most {maximum_days} days"
        )
    return start, end


def collected_through(connection) -> int | None:
    row = connection.execute(
        "SELECT value FROM state WHERE key = 'collected_through_us'"
    ).fetchone()
    return int(row[0]) if row else None


def health_snapshot(path, now_us=None):
    now_us = int(time.time() * 1_000_000) if now_us is None else now_us
    with readonly_connection(path) as connection:
        through = collected_through(connection)
        count, oldest, newest = connection.execute(
            "SELECT COUNT(*), MIN(ts_us), MAX(ts_us) FROM samples"
        ).fetchone()
    return {
        "status": "ok" if through is not None else "starting",
        "node": socket.gethostname(),
        "collected_through_us": through,
        "collection_lag_seconds": None if through is None else max(0.0, (now_us - through) / 1_000_000),
        "samples": count,
        "samples_oldest_us": oldest,
        "samples_newest_us": newest,
    }


def samples_snapshot(path, query):
    start, end = window_query(query, SAMPLES_MAX_DAYS)
    metric = query.get("metric", [None])[0]
    sql = "SELECT ts_us, metric, detail, value FROM samples WHERE ts_us >= ? AND ts_us < ?"
    parameters = [start * 1_000_000, end * 1_000_000]
    if metric:
        sql += " AND metric = ?"
        parameters.append(metric)
    sql += f" ORDER BY ts_us, metric, detail LIMIT {SAMPLES_LIMIT + 1}"
    with readonly_connection(path) as connection:
        rows = connection.execute(sql, parameters).fetchall()
        through = collected_through(connection)
    # One row beyond the limit is fetched only to make the cut visible
    truncated = len(rows) > SAMPLES_LIMIT
    return {
        "from": start,
        "to": end,
        "truncated": truncated,
        "collected_through_us": through,
        "rows": [
            {"ts_us": ts, "metric": name, "dimensions": dimensions(name, detail), "value": value}
            for ts, name, detail, value in rows[:SAMPLES_LIMIT]
        ],
    }


def aggregate_snapshot(path, query):
    resolution_name = query.get("resolution", ["hour"])[0]
    if resolution_name not in RESOLUTIONS:
        raise ValueError("resolution must be hour or day")
    step = RESOLUTIONS[resolution_name]
    start, end = window_query(query, RETENTION_DAYS)
    metric = query.get("metric", [None])[0]
    # A bucket belongs to the answer when its start lies in [from, to), the
    # mail host's rule, so the samples read are those of exactly those buckets
    first = -(-start // step) * step
    last = -(-end // step) * step
    window = [first * 1_000_000, last * 1_000_000]
    counters = sorted(COUNTERS)
    marks = ",".join("?" * len(counters))
    only = " AND metric = ?" if metric else ""
    extra = [metric] if metric else []

    with readonly_connection(path) as connection:
        gauges = connection.execute(
            f"""
            SELECT ts_us / 1000000 / ? * ? AS bucket, metric, detail,
                   COUNT(*), SUM(value), MIN(value), MAX(value)
            FROM samples
            WHERE ts_us >= ? AND ts_us < ? AND metric NOT IN ({marks}){only}
            GROUP BY bucket, metric, detail
            """,
            [step, step, *window, *counters, *extra],
        ).fetchall()
        raw = connection.execute(
            f"""
            SELECT ts_us, metric, detail, value FROM samples
            WHERE ts_us >= ? AND ts_us < ? AND metric IN ({marks}){only}
            ORDER BY metric, detail, ts_us
            """,
            [*window, *counters, *extra],
        ).fetchall()
        # The last sample before the window is each counter's baseline, so
        # the first step inside the window is not lost at its edge. SQLite
        # takes the bare value column from the row that holds MAX(ts_us)
        baselines = {
            (name, detail): value
            for name, detail, value, _ts in connection.execute(
                f"""
                SELECT metric, detail, value, MAX(ts_us) FROM samples
                WHERE ts_us < ? AND metric IN ({marks}){only}
                GROUP BY metric, detail
                """,
                [window[0], *counters, *extra],
            )
        }

    buckets = {
        (bucket, name, detail): ("gauge", count, total, low, high)
        for bucket, name, detail, count, total, low, high in gauges
    }
    previous_series, previous = None, None
    for ts, name, detail, value in raw:
        if (name, detail) != previous_series:
            previous_series = (name, detail)
            previous = baselines.get(previous_series)
        if previous is not None:
            change = clamped_delta(value, previous)
            key = (ts // 1_000_000 // step * step, name, detail)
            _kind, count, total, low, high = buckets.get(key, ("counter", 0, 0.0, change, change))
            buckets[key] = ("counter", count + 1, total + change, min(low, change), max(high, change))
        previous = value

    ordered = sorted(buckets.items())
    truncated = len(ordered) > AGGREGATES_LIMIT
    return {
        "resolution": resolution_name,
        "from": start,
        "to": end,
        "truncated": truncated,
        "rows": [
            {
                "bucket_start": bucket,
                "metric": name,
                "kind": kind,
                "dimensions": dimensions(name, detail),
                "samples": count,
                "total": total,
                "minimum": low,
                "maximum": high,
            }
            for (bucket, name, detail), (kind, count, total, low, high) in ordered[:AGGREGATES_LIMIT]
        ],
    }


def handler_for(database):
    class Handler(BaseHTTPRequestHandler):
        # A peer that opens a connection and sends nothing must not hold the
        # worker; the service's RuntimeMaxSec is the backstop behind this
        timeout = 10

        def send_json(self, status, payload):
            body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            request = urlparse(self.path)
            try:
                if request.path == "/v1/health":
                    payload = health_snapshot(database)
                elif request.path == "/v1/samples":
                    payload = samples_snapshot(database, parse_qs(request.query))
                elif request.path == "/v1/aggregates":
                    payload = aggregate_snapshot(database, parse_qs(request.query))
                else:
                    self.send_json(404, {"error": "not found"})
                    return
                self.send_json(200, payload)
            except (OSError, sqlite3.Error):
                self.send_json(503, {"error": "metrics database unavailable"})
            except ValueError as error:
                self.send_json(400, {"error": str(error)})

        def log_message(self, format, *args):  # noqa: A002 — the base class names it
            return

    return Handler


def serve_connection(connection: socket.socket) -> None:
    """Answer the one request on a connection systemd accepted for us.

    The socket unit runs with Accept=yes, so every connection gets a fresh,
    sandboxed process with the connection on fd 0, and the process ends with
    the answer. Nothing stays resident between requests.
    """
    try:
        peer = connection.getpeername()
    except OSError:
        peer = ("", 0)
    try:
        handler_for(DB_PATH)(connection, peer if isinstance(peer, tuple) else ("", 0), None)
    finally:
        with contextlib.suppress(OSError):
            connection.shutdown(socket.SHUT_RDWR)
        connection.close()


def main(argv: list[str]) -> int:
    if argv == ["collect"]:
        return collect()
    if argv == ["serve"]:
        serve_connection(socket.socket(fileno=0))
        return 0
    print("usage: skibidi-metrics collect | serve", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
