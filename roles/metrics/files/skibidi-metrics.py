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

After each collection the newest value of every series is pushed to the
station's Pushgateway, when the node names a station. `push` does the push
alone. docs/metrics-api.md, "The push", is the contract.
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


# What the station's dashboard calls each metric, with its help text. The type
# follows COUNTERS. A metric missing here is sampled and served by the API but
# never pushed, and a test holds this table to the probes below
PROMETHEUS = {
    "load1": ("vpn_load1", "One-minute load average"),
    "mem_used_ratio": ("vpn_memory_used_ratio", "Share of memory in use"),
    "disk_used_ratio": ("vpn_disk_used_ratio", "Share of the root file system in use"),
    "disk_total_bytes": ("vpn_disk_total_bytes", "Size of the root file system"),
    "uptime_seconds": ("vpn_uptime_seconds", "Seconds since boot"),
    "conntrack_used_ratio": ("vpn_conntrack_used_ratio", "Share of the connection tracking table in use"),
    "conntrack_count": ("vpn_conntrack_entries", "Entries in the connection tracking table"),
    "established_sockets": ("vpn_established_sockets", "TCP sockets in the ESTABLISHED state"),
    "established_no_timer": (
        "vpn_established_sockets_without_timer",
        "ESTABLISHED sockets with no timer armed, the shape of the timeout bug",
    ),
    "f2b_failed_total": ("vpn_fail2ban_failed_total", "Failed attempts a fail2ban jail counted"),
    "f2b_banned_total": ("vpn_fail2ban_banned_total", "Bans a fail2ban jail issued"),
    "f2b_banned_now": ("vpn_fail2ban_banned", "Addresses a fail2ban jail holds banned now"),
    "unit_restarts": ("vpn_unit_restarts_total", "Automatic restarts of a watched unit"),
    "timer_last_fired": (
        "vpn_timer_last_fired_timestamp_seconds",
        "Unix time a watched timer last fired",
    ),
    "pkg_updates": ("vpn_pending_updates", "Package updates apt would install"),
    "reboot_required": ("vpn_reboot_required", "1 when a package update asks for a reboot"),
}

UFW_TOTAL = "ufw_drops_total"


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


def state_value(connection: sqlite3.Connection, key: str):
    row = connection.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def set_state(connection: sqlite3.Connection, key: str, value) -> None:
    connection.execute(
        "INSERT INTO state (key, value) VALUES (?, ?) "
        "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (key, str(value)),
    )


def push_library():
    # Imported when a push needs it, so a node whose library has not arrived
    # yet still samples and still serves its API
    lib = os.environ.get("SKIBIDI_LIB", "/usr/local/lib/skibidi")
    if lib not in sys.path:
        sys.path.insert(0, lib)
    import skibidi_push

    return skibidi_push


def open_problems(environ):
    """The urgent problems this node reports of itself, as (cause, summary),
    or None where the node does not say where the check records them. They
    are the failures the last skibidi-check left, read the way the daily list
    reads them. A cause that repeats counts once: two series with one key
    would be one alert twice"""
    record = environ.get("SKIBIDI_CHECK_RESULT")
    if not record:
        return None
    import skibidi_problems

    found = {}
    for cause, message in skibidi_problems.check_records(record, float(environ["SKIBIDI_CHECK_MAX_AGE_HOURS"])):
        found.setdefault(cause, skibidi_problems.summary(message))
    return list(found.items())


def traffic_text(environ, taken, now):
    """The master's traffic, a file the reporter writes, or "" when there is
    none to add. A file nobody refreshed within the window is left out, so a
    reporter that stopped does not keep old numbers on the dashboard, and a
    file the station would refuse is left out with a line in the journal, so
    it cannot take this node's sign of life with it"""
    path = environ.get("SKIBIDI_PUSH_TEXTFILE")
    if not path or not Path(path).exists():
        return ""
    skibidi_push = push_library()
    try:
        if now - Path(path).stat().st_mtime > skibidi_push.LATEST_WINDOW_SECONDS:
            return ""
        text = Path(path).read_text()
        skibidi_push.validate_text(text, taken)
    except (OSError, ValueError) as error:
        print(f"push: the traffic file is left out: {error}", file=sys.stderr)
        return ""
    return text


# Who knocks: the attempts of the last day and the bans in it, read from
# fail2ban's own log when the push runs. Only the busiest few addresses are
# pushed, because every address is a series of its own at the station
ATTACK_WINDOW_SECONDS = 86400
ATTACK_TOP = 10
LOG_BLOCK = 1 << 16
F2B_LINE = re.compile(
    r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ fail2ban\.\w+ +\[\d+\]: +\w+ +\[([^]]+)\] (Found|Ban) (\S+)"
)
F2B_STAMP = re.compile(rb"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),")


def log_stamp(text) -> float | None:
    """The time of a log line, which fail2ban writes in local time"""
    try:
        return time.mktime(time.strptime(text, "%Y-%m-%d %H:%M:%S"))
    except ValueError:
        return None


def log_since(path: Path, cutoff: float) -> list[tuple]:
    """(time, jail, event, address) of each finding and ban written at or
    after cutoff. The log is read back from its end only as far as the
    cutoff, because it runs to weeks and this runs every minute"""
    with path.open("rb") as handle:
        position = handle.seek(0, os.SEEK_END)
        data = b""
        while position > 0:
            step = min(LOG_BLOCK, position)
            position -= step
            handle.seek(position)
            data = handle.read(step) + data
            # A block that starts mid-line starts with a fragment, which has no
            # whole stamp and so is never taken for the oldest line
            first = next((match for match in map(F2B_STAMP.match, data.split(b"\n")) if match), None)
            stamp = log_stamp(first.group(1).decode()) if first else None
            if stamp is not None and stamp < cutoff:
                break
    found = []
    for raw in data.decode(errors="replace").splitlines():
        match = F2B_LINE.match(raw)
        stamp = log_stamp(match.group(1)) if match else None
        if match and stamp is not None and stamp >= cutoff:
            found.append((stamp, match.group(2), match.group(3), match.group(4)))
    return found


def attacker_families(environ, now):
    """The busiest addresses of the day by attempts, and the latest bans, in
    the jails that face attackers. A jail that bans the operator's own
    clients, or one that reads fail2ban's own bans as its findings, would
    count the wrong people, so the role names the jails"""
    path = environ.get("SKIBIDI_FAIL2BAN_LOG")
    jails = set(environ.get("SKIBIDI_ATTACK_JAILS", "").split())
    if not path or not jails:
        return []
    attempts: dict = {}
    bans: dict = {}
    for candidate in (Path(f"{path}.1"), Path(path)):
        try:
            events = log_since(candidate, now - ATTACK_WINDOW_SECONDS)
        except FileNotFoundError:
            continue
        except OSError as error:
            print(f"push: the fail2ban log is left out: {error}", file=sys.stderr)
            continue
        for stamp, jail, event, address in events:
            if jail not in jails:
                continue
            if event == "Found":
                attempts[address] = attempts.get(address, 0) + 1
            else:
                bans[(jail, address)] = max(bans.get((jail, address), 0.0), stamp)
    skibidi_push = push_library()
    families = []
    if attempts:
        busiest = sorted(attempts.items(), key=lambda item: (-item[1], item[0]))[:ATTACK_TOP]
        families.append(skibidi_push.family(
            "vpn_fail2ban_top_attempts", "gauge",
            "Failed attempts in the last day of the addresses that tried most",
            [({"ip": address}, float(count)) for address, count in busiest],
        ))
    if bans:
        latest = sorted(bans.items(), key=lambda item: -item[1])[:ATTACK_TOP]
        families.append(skibidi_push.family(
            "vpn_fail2ban_recent_ban_timestamp_seconds", "gauge",
            "When each of the latest banned addresses was banned",
            [({"jail": jail, "ip": address}, stamp) for (jail, address), stamp in latest],
        ))
    return families


def push_families(rows, ufw_total, problems=None):
    """The dashboard's view of the newest rows: (ts, metric, detail, value)
    in, Prometheus families out"""
    skibidi_push = push_library()
    grouped: dict = {}
    for (metric, detail), (_ts, value) in sorted(skibidi_push.latest(rows).items()):
        if metric not in PROMETHEUS:
            continue
        label = DIMENSIONS.get(metric, "detail")
        grouped.setdefault(metric, []).append(({label: detail} if detail else {}, value))
    families = [
        skibidi_push.family(
            PROMETHEUS[metric][0],
            "counter" if metric in COUNTERS else "gauge",
            PROMETHEUS[metric][1],
            samples,
        )
        for metric, samples in grouped.items()
    ]
    if ufw_total is not None:
        families.append(skibidi_push.family(
            "vpn_ufw_drops_total", "counter", "Packets the firewall dropped and logged", [({}, ufw_total)]
        ))
    # One series per open problem, and none when nothing is open. The push
    # replaces the whole group, so a problem that was solved is missing from
    # the next body and leaves the station with it
    if problems:
        families.append(skibidi_push.family(
            "node_problem", "gauge",
            "One unresolved problem this node reports of itself, by cause",
            [({"key": cause, "summary": text}, 1) for cause, text in problems],
        ))
    return families


def push_latest(now_us: int) -> int:
    """Push the newest samples, the open problems and, on the master, the
    traffic file, as the whole of this host's group. 0 when pushed, 3 when the
    node names no station, 1 when the push failed. A failure is a line in the
    journal, never a lost sample, and the station's alert on a stale push is
    what raises it. The alert unit runs this and mails only when it is not 0"""
    try:
        skibidi_push = push_library()
    except ImportError as error:
        print(f"push: {error}", file=sys.stderr)
        return 1
    try:
        station = skibidi_push.target(os.environ)
        with connect() as connection:
            if station is None:
                # Said once, not every ten minutes: a node that names no
                # station is a decision, and a journal line per run would
                # bury the lines that are not
                if state_value(connection, "push_unconfigured_noted") is None:
                    print("push: this node names no backup station, so nothing is pushed", file=sys.stderr)
                    set_state(connection, "push_unconfigured_noted", now_us)
                return 3
            connection.execute("DELETE FROM state WHERE key = 'push_unconfigured_noted'")
            rows = connection.execute(
                "SELECT ts_us, metric, detail, value FROM samples WHERE ts_us >= ?",
                (now_us - skibidi_push.LATEST_WINDOW_SECONDS * 1_000_000,),
            ).fetchall()
            total = state_value(connection, UFW_TOTAL)
        families = push_families(rows, None if total is None else float(total), open_problems(os.environ))
        families += attacker_families(os.environ, time.time())
        body = skibidi_push.render(families) + traffic_text(
            os.environ, {item["name"] for item in families}, time.time()
        )
        skibidi_push.push_text(station, body)
    except (skibidi_push.PushError, ValueError, sqlite3.Error) as error:
        print(f"push: {error}", file=sys.stderr)
        return 1
    return 0


def collect(push: bool = True) -> int:
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
        # The drops of a run are a count over its interval, which a dashboard
        # cannot add up from pushes that repeat. The running total is a
        # counter, and it grows by exactly what the run stored
        counted = [value for _ts, metric, _detail, value in rows if metric == "ufw_drops"]
        if counted:
            total = float(state_value(connection, UFW_TOTAL) or 0) + sum(counted)
            set_state(connection, UFW_TOTAL, total)
        # Advanced even when probes failed: freshness means the collector ran,
        # and which metrics are missing is the reader's question to answer
        set_state(connection, "collected_through_us", now_us)
    # After the commit, so that a station which hangs holds up no sample
    if push:
        push_latest(now_us)
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
    if argv == ["collect", "--no-push"]:
        return collect(push=False)
    if argv == ["push"]:
        return push_latest(int(time.time() * 1_000_000))
    if argv == ["serve"]:
        serve_connection(socket.socket(fileno=0))
        return 0
    print("usage: skibidi-metrics collect [--no-push] | push | serve", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
