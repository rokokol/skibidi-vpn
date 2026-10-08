#!/usr/bin/env python3
"""The weekly letter. One message from the master, covering the whole fleet.

Everything here reads — the panel's own database, opened read-only, every
node's metric store through its read-only API on the tailnet (this master's
own included), and this host's own daily snapshots — and writes one multipart
message.

Two rules the layout hangs on, both inherited from the mail host's report. A
section with nothing to say is omitted entirely, in text and HTML alike — but
the letter itself is always sent, so a missing Monday letter can only ever mean
the reporting is broken. And there is no permanent status banner: an alert
block exists only when something is wrong, and it also prefixes the subject,
so trouble is visible in a notification without opening anything.

No API and no token: the master holds the panel's database, and reading it is
a file permission rather than a credential. The panel's CLI can only mint a
token by rotating the one it owns, which would knock out whoever else held it;
the database asks nothing of anyone. The columns read here — inbounds,
client_traffics, settings, nodes — are the ones the panel has carried since its
first releases, and a release that moves one fails the deploy-time rehearsal,
not a Monday.
"""

from __future__ import annotations

import datetime as dt
import html
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from email.message import EmailMessage
from pathlib import Path
from zoneinfo import ZoneInfo

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover — Ubuntu 24.04 ships 3.12
    tomllib = None

DAY_US = 86400 * 1_000_000

# The neutral fallback; the deployed master overrides it with the theme's own
# letter file, delivered as /etc/skibidi/ddlc-mail.json at deploy time
PALETTE_DEFAULTS = {
    "paper": "#ffffff",
    "ink": "#1f2430",
    "muted": "#5b6472",
    "accent": "#3b6ea5",
    "ok": "#3f7d4e",
    "warn": "#b3423a",
    "ash": "#d8dce3",
    "blush": "#eef1f5",
    "divider": "#c3cbd6",
}

# What each semantic slot here means in the theme's role vocabulary. The role
# names are the contract ddlc-themes keeps for letters, which outlives any
# renaming of the palette's own character colours
THEME_ROLES = {
    "paper": "ground",
    "ink": "text",
    "muted": "muted",
    "ash": "grid",
    "blush": "code-ground",
    "divider": "line",
    "warn": "danger",
    "accent": "accent",
    "ok": "ok",
}

THEME_CYCLE = tuple(f"series-{index}" for index in range(1, 6))


def load_theme(path: str | None = None) -> dict:
    """The theme's letter file: its light colours, its faces and a ready style
    value for each element, all literal, because mail clients drop var().

    A machine nobody themed has none, and gets an empty theme."""
    file = Path(path or os.environ.get("SKIBIDI_MAIL_FILE", "/etc/skibidi/ddlc-mail.json"))
    try:
        return json.loads(file.read_text())
    except (OSError, ValueError):
        return {}


def load_palette(theme: dict) -> dict:
    """Semantic slots resolved against the theme; without one the neutral
    defaults stand, so a report on a machine nobody themed still renders."""
    colors = theme.get("colors", {})
    palette: dict = dict(PALETTE_DEFAULTS)
    for slot, role in THEME_ROLES.items():
        if role in colors:
            palette[slot] = colors[role]
    if all(role in colors for role in THEME_CYCLE):
        palette["cycle"] = [colors[role] for role in THEME_CYCLE]
    else:
        palette["cycle"] = [palette[slot] for slot in ("accent", "warn", "muted", "ok", "ink")]
    return palette


THEME = load_theme()
PALETTE = load_palette(THEME)


def style(element: str, extra: str = "") -> str:
    """The theme's style value for an element, with what this element alone
    needs on top; a later declaration in a style attribute wins. Unthemed, an
    element keeps the reader's default look and only the extra"""
    return ";".join(part for part in (THEME.get("styles", {}).get(element, ""), extra) if part)


# ---------------------------------------------------------------- config


def load_config(path: str | None = None) -> dict:
    file = Path(path or os.environ.get("SKIBIDI_REPORT_CONFIG", "/etc/skibidi/report.toml"))
    with file.open("rb") as handle:
        config = tomllib.load(handle)
    config.setdefault("report", {})
    config.setdefault("panel", {})
    config.setdefault("paths", {})
    config.setdefault("nodes", [])
    config.setdefault("metrics", {})
    config["metrics"].setdefault("port", 9099)
    paths = config["paths"]
    paths.setdefault("state_dir", "/var/lib/skibidi-report")
    paths.setdefault("sendmail", "/usr/sbin/sendmail")
    panel = config["panel"]
    panel.setdefault("db", "/etc/x-ui/x-ui.db")
    panel.setdefault("xui_bin", "/usr/local/x-ui/x-ui")
    panel.setdefault("xray_bin", "/usr/local/x-ui/bin/xray-linux-amd64")
    return config


def report_window(now=None, timezone_name="Europe/Moscow", hour=9, weekday=0):
    """The week that ended at the configured weekday and hour.

    The hour is stated once, in the config that also writes the timer's
    OnCalendar — computing the window from "now" rather than from the firing
    time is what keeps a delayed or manual run reporting the same week.
    """
    zone = ZoneInfo(timezone_name)
    now = dt.datetime.now(dt.UTC) if now is None else now.astimezone(dt.UTC)
    local = now.astimezone(zone)
    end = dt.datetime.combine(local.date(), dt.time(hour), zone)
    end -= dt.timedelta(days=(local.date().weekday() - weekday) % 7)
    if local < end:
        end -= dt.timedelta(days=7)
    start = end - dt.timedelta(days=7)
    return int(start.timestamp() * 1_000_000), int(end.timestamp() * 1_000_000)


# ---------------------------------------------------------------- masking


def client_label(value) -> str:
    """The label as the panel carries it. This letter goes to the fleet's own
    operator over their own mail path — masking their family's names from them
    would protect nobody. What stays out of every letter and snapshot is the
    credential half: UUIDs, subscription ids, keys."""
    return str(value or "")


def format_bytes(count) -> str:
    count = float(count)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if count < 1024 or unit == "TiB":
            return f"{count:.1f} {unit}" if unit != "B" else f"{int(count)} B"
        count /= 1024
    return f"{count:.1f} TiB"


# ---------------------------------------------------------------- panel database


class PanelError(Exception):
    pass


def open_panel_db(path: str) -> sqlite3.Connection:
    """The panel's database, opened so that this process cannot write it.

    mode=ro refuses every write below SQL level and never creates a missing
    file, so a bug here cannot damage what the panel owns, and a master with
    no panel reads as an error rather than as an empty fleet.
    """
    if not Path(path).is_file():
        raise PanelError(f"no panel database at {path}")
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30)
    connection.execute("PRAGMA query_only = ON")
    connection.row_factory = sqlite3.Row
    return connection


def db_inbounds(connection: sqlite3.Connection) -> list[dict]:
    """Inbounds shaped the way the API served them, so everything downstream —
    the sanitiser, the traffic deltas, the client questions — reads one shape.
    A panel release that renames a column fails here, in one place, and the
    deploy-time rehearsal is where it fails."""
    inbounds = []
    rows = connection.execute(
        "SELECT id, up, down, remark, enable, port, protocol, settings, node_id FROM inbounds"
    ).fetchall()
    for row in rows:
        stats = connection.execute(
            "SELECT email, up, down, total, expiry_time, enable, last_online "
            "FROM client_traffics WHERE inbound_id = ?",
            (row["id"],),
        ).fetchall()
        inbounds.append({
            "id": row["id"],
            "up": row["up"],
            "down": row["down"],
            "remark": row["remark"],
            "enable": bool(row["enable"]),
            "port": row["port"],
            "protocol": row["protocol"],
            "settings": row["settings"],
            "nodeId": row["node_id"],
            "clientStats": [
                {
                    "email": stat["email"],
                    "up": stat["up"],
                    "down": stat["down"],
                    "total": stat["total"],
                    "expiryTime": stat["expiry_time"],
                    "enable": bool(stat["enable"]),
                    "lastOnline": stat["last_online"],
                }
                for stat in stats
            ],
        })
    return inbounds


def db_nodes(connection: sqlite3.Connection) -> list[dict]:
    """The fleet as the master last heard it: the panel persists each node's
    heartbeat, latency and versions beside its address, so the letter's view
    of the nodes needs no token either. A panel without node mode has no
    table, which is an empty fleet rather than an error."""
    try:
        rows = connection.execute(
            "SELECT name, remark, status, last_heartbeat, latency_ms, cpu_pct, mem_pct, "
            "panel_version, xray_version FROM nodes"
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    return [dict(row) for row in rows]


def binary_version(argv: list[str]) -> str:
    """The first version-looking word a binary prints for its version flag."""
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    match = re.search(r"\d+\.\d+(\.\d+)?", result.stdout + result.stderr)
    return match.group(0) if match else ""


def client_traffic(client: dict) -> tuple[int, int, int]:
    """up, down, lastOnline of a client row as db_inbounds shapes it."""
    return (
        int(client.get("up") or 0),
        int(client.get("down") or 0),
        int(client.get("lastOnline") or 0),
    )


# ---------------------------------------------------------------- snapshots


def sanitise_inbound(inbound: dict) -> dict:
    """The structure of an inbound without any of its secrets.

    Stored weekly in /var/lib, so it must never carry what the database
    carries: no client UUIDs, no subscription ids, no Reality keys, no stream
    settings at all. Labels are masked the way every rendering here masks them
    — a snapshot is just a letter that has not been sent yet.
    """
    clients = []
    stats = inbound.get("clientStats") or []
    settings = {}
    try:
        settings = json.loads(inbound.get("settings") or "{}")
    except (TypeError, json.JSONDecodeError):
        pass
    for client in settings.get("clients") or [{"email": s.get("email")} for s in stats]:
        clients.append(client_label(client.get("email")))
    return {
        "key": f"{inbound.get('nodeId') or inbound.get('node_id') or 0}"
               f"/{inbound.get('protocol')}/{inbound.get('port')}",
        "remark": str(inbound.get("remark") or ""),
        "enable": bool(inbound.get("enable")),
        "clients": sorted(clients),
    }


def db_routing(connection: sqlite3.Connection) -> list:
    """Routing rules out of the xray template the panel keeps in its settings.

    Only the rules, and never their `user` field: the structure is what the
    Monday diff compares, and a client name belongs in the client sections.
    """
    row = connection.execute(
        "SELECT value FROM settings WHERE key = 'xrayTemplateConfig'"
    ).fetchone()
    if not row or not row["value"]:
        return []
    setting = json.loads(row["value"])
    rules = (((setting or {}).get("routing")) or {}).get("rules") or []
    kept = []
    for rule in rules:
        kept.append({k: rule[k] for k in sorted(rule) if k not in ("user",)})
    return kept


def snapshot_path(state_dir: str, day: dt.date) -> Path:
    return Path(state_dir) / f"snapshot-{day.isoformat()}.json"


def take_snapshot(config: dict, now=None) -> dict:
    """The daily record everything weekly is computed from: cumulative traffic
    per inbound and client (deltas are the reader's job, clamped there), and
    the sanitised structure the Monday diff compares."""
    report = config["report"]
    zone = ZoneInfo(report.get("timezone", "Europe/Moscow"))
    now = now or dt.datetime.now(dt.UTC)
    connection = open_panel_db(config["panel"]["db"])

    inbounds = db_inbounds(connection)
    traffic = {"inbounds": {}, "clients": {}}
    structure = {"inbounds": [], "routing": []}
    for inbound in inbounds:
        sanitised = sanitise_inbound(inbound)
        structure["inbounds"].append(sanitised)
        traffic["inbounds"][sanitised["key"]] = {
            "remark": sanitised["remark"],
            "up": int(inbound.get("up") or 0),
            "down": int(inbound.get("down") or 0),
        }
        for client in inbound.get("clientStats") or []:
            up, down, last_online = client_traffic(client)
            label = client_label(client.get("email"))
            traffic["clients"][label] = {
                "up": up,
                "down": down,
                "total": int(client.get("total") or 0),
                "expiry": int(client.get("expiryTime") or 0),
                "enable": bool(client.get("enable", True)),
                "last_online": last_online,
            }
    try:
        structure["routing"] = db_routing(connection)
    except (sqlite3.Error, json.JSONDecodeError, AttributeError) as error:
        print(f"routing snapshot: {error}", file=sys.stderr)
    connection.close()

    payload = {
        "taken_us": int(now.timestamp() * 1_000_000),
        "traffic": traffic,
        "structure": structure,
    }
    state_dir = config["paths"]["state_dir"]
    Path(state_dir).mkdir(mode=0o700, parents=True, exist_ok=True)
    path = snapshot_path(state_dir, now.astimezone(zone).date())
    path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    path.chmod(0o600)
    for old in sorted(Path(state_dir).glob("snapshot-*.json"))[:-30]:
        old.unlink()
    return payload


def load_snapshots(state_dir: str, start: dt.date, end: dt.date) -> dict[dt.date, dict]:
    snapshots = {}
    day = start
    while day <= end:
        path = snapshot_path(state_dir, day)
        if path.is_file():
            try:
                snapshots[day] = json.loads(path.read_text())
            except json.JSONDecodeError:
                pass
        day += dt.timedelta(days=1)
    return snapshots


def clamped_delta(new: int, old: int) -> int:
    # A counter that went down was reset; the honest number for the interval
    # is everything the new counter has seen, not a negative week
    return new - old if new >= old else new


def daily_inbound_series(snapshots: dict[dt.date, dict]) -> list[tuple[dt.date, dict[str, int]]]:
    days = sorted(snapshots)
    series = []
    for previous, current in zip(days, days[1:]):
        before = snapshots[previous]["traffic"]["inbounds"]
        after = snapshots[current]["traffic"]["inbounds"]
        totals = {}
        for key, row in after.items():
            old = before.get(key, {"up": 0, "down": 0})
            delta = clamped_delta(row["up"], old["up"]) + clamped_delta(row["down"], old["down"])
            if delta:
                totals[row["remark"] or key] = delta
        series.append((current, totals))
    return series


def weekly_client_deltas(snapshots: dict[dt.date, dict]) -> list[tuple[str, int]]:
    days = sorted(snapshots)
    if len(days) < 2:
        return []
    first, last = snapshots[days[0]]["traffic"]["clients"], snapshots[days[-1]]["traffic"]["clients"]
    deltas = []
    for label, row in last.items():
        old = first.get(label, {"up": 0, "down": 0})
        delta = clamped_delta(row["up"], old["up"]) + clamped_delta(row["down"], old["down"])
        if delta:
            deltas.append((label, delta))
    return sorted(deltas, key=lambda pair: -pair[1])


def structure_diff(before: dict | None, after: dict | None) -> list[str]:
    """The section that answers "I touched something and forgot"."""
    if not before or not after:
        return []
    lines = []
    old = {row["key"]: row for row in before.get("inbounds", [])}
    new = {row["key"]: row for row in after.get("inbounds", [])}
    for key in sorted(new.keys() - old.keys()):
        lines.append(f"inbound added: {new[key]['remark'] or key}")
    for key in sorted(old.keys() - new.keys()):
        lines.append(f"inbound removed: {old[key]['remark'] or key}")
    for key in sorted(old.keys() & new.keys()):
        was, now = old[key], new[key]
        if was["enable"] != now["enable"]:
            state = "enabled" if now["enable"] else "disabled"
            lines.append(f"inbound {state}: {now['remark'] or key}")
        joined, left = set(now["clients"]) - set(was["clients"]), set(was["clients"]) - set(now["clients"])
        if joined:
            lines.append(f"clients added to {now['remark'] or key}: {', '.join(sorted(joined))}")
        if left:
            lines.append(f"clients removed from {now['remark'] or key}: {', '.join(sorted(left))}")
    old_rules = [json.dumps(r, sort_keys=True) for r in before.get("routing", [])]
    new_rules = [json.dumps(r, sort_keys=True) for r in after.get("routing", [])]
    added = [r for r in new_rules if r not in old_rules]
    removed = [r for r in old_rules if r not in new_rules]
    if added or removed:
        lines.append(f"routing rules: {len(added)} added, {len(removed)} removed")
    return lines


# ---------------------------------------------------------------- OS metrics


class StaleWindow(Exception):
    pass


def fetch(config: dict, node: dict, path: str, query: dict | None = None) -> dict:
    """One GET against a node's metrics API, every failure a StaleWindow.

    The API is plain HTTP on the tailnet, where WireGuard already encrypts and
    authenticates below it; docs/metrics-api.md is the contract.
    """
    host = node["host"]
    if ":" in host:
        host = f"[{host}]"
    url = f"http://{host}:{config['metrics']['port']}{path}"
    if query:
        url += "?" + urllib.parse.urlencode(query)
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        with error:
            try:
                reason = json.loads(error.read()).get("error", "")
            except (ValueError, AttributeError, OSError):
                reason = ""
        raise StaleWindow(f"HTTP {error.code} {reason}".strip()) from None
    except (urllib.error.URLError, OSError) as error:
        raise StaleWindow(str(getattr(error, "reason", error)) or "no answer") from None


def pull_node(config: dict, node: dict, start_us: int, end_us: int) -> dict:
    """A node's window as the letter reads it: rows of (ts_us, metric, detail, value)."""
    payload = fetch(config, node, "/v1/samples",
                    {"from": start_us // 1_000_000, "to": end_us // 1_000_000})
    # A cut week reads exactly like a quiet one in every counter, so it is
    # refused rather than reported
    if payload.get("truncated"):
        raise StaleWindow("answered with a cut window")
    return {
        "collected_through_us": payload.get("collected_through_us") or 0,
        "samples": [
            [row["ts_us"], row["metric"], next(iter(row["dimensions"].values()), ""), row["value"]]
            for row in payload["rows"]
        ],
    }


def wait_for_collector(config: dict, master_name: str, end_us: int, deadline: float,
                       interval: float = 5) -> bool:
    """True once the master's collector has crossed the window's end."""
    master = next((node for node in config["nodes"] if node["name"] == master_name), None)
    while master is not None:
        try:
            if (fetch(config, master, "/v1/health").get("collected_through_us") or 0) >= end_us:
                return True
        except (StaleWindow, json.JSONDecodeError):
            pass
        if time.monotonic() >= deadline:
            break
        time.sleep(interval)
    return False


def probe(config: dict) -> int:
    """The deploy's question, asked with the letter's own mouth.

    Runs pull_node itself — same port, same path, same configured address —
    so nothing can drift between what the deploy proved and what Monday does.
    A hand-built check here once passed while the real pull was broken; that
    class of gap is exactly what reusing the code closes. The last hour, so the
    answer is small and still has to come from a store that exists.
    """
    failures = []
    end_us = int(time.time()) * 1_000_000
    for node in config["nodes"]:
        try:
            payload = pull_node(config, node, end_us - 3600 * 1_000_000, end_us)
        except (StaleWindow, json.JSONDecodeError, KeyError, TypeError) as error:
            failures.append(f"{node['name']}: {error}")
            continue
        if "samples" not in payload:
            failures.append(f"{node['name']}: answered, but not with samples")
    for line in failures:
        print(line, file=sys.stderr)
    print(f"probed {len(config['nodes'])} node(s), {len(failures)} refused")
    return 1 if failures else 0


def gather_metrics(config: dict, start_us: int, end_us: int):
    """Every node's window, with absence recorded rather than smoothed over.

    A node that was down looks exactly like a quiet one in every counter it
    failed to deliver, so the letter says which nodes did not answer instead
    of letting their silence read as health.
    """
    exports, unreachable, stale = {}, [], []
    for node in config["nodes"]:
        try:
            exports[node["name"]] = pull_node(config, node, start_us, end_us)
        except (StaleWindow, json.JSONDecodeError, KeyError, TypeError) as error:
            unreachable.append((node["name"], str(error)))
    for name, export in exports.items():
        if export.get("collected_through_us", 0) < end_us - 30 * 60 * 1_000_000:
            stale.append(name)
    return exports, unreachable, stale


def series(export: dict, metric: str, detail: str | None = None):
    return [
        (ts, det, value)
        for ts, met, det, value in export.get("samples", [])
        if met == metric and (detail is None or det == detail)
    ]


def last_value(export: dict, metric: str, detail: str | None = None, default=None):
    rows = series(export, metric, detail)
    return rows[-1][2] if rows else default


def max_value(export: dict, metric: str, detail: str | None = None, default=None):
    rows = series(export, metric, detail)
    return max(row[2] for row in rows) if rows else default


def counter_week_delta(export: dict, metric: str, detail: str) -> int:
    """A cumulative counter turned into this week's count, reset-tolerant:
    every upward step is kept, a drop restarts from the new absolute."""
    rows = series(export, metric, detail)
    total, previous = 0, None
    for _ts, _detail, value in rows:
        if previous is not None:
            total += clamped_delta(int(value), int(previous))
        previous = value
    return total


def daily_sums(export: dict, metric: str, zone: ZoneInfo) -> dict[dt.date, int]:
    days: dict[dt.date, int] = defaultdict(int)
    for ts, _detail, value in series(export, metric):
        day = dt.datetime.fromtimestamp(ts / 1_000_000, dt.UTC).astimezone(zone).date()
        days[day] += int(value)
    return dict(days)


def health_rows(exports: dict[str, dict]) -> list[dict]:
    rows = []
    for name, export in sorted(exports.items()):
        rows.append({
            "node": name,
            "uptime": last_value(export, "uptime_seconds"),
            "load_max": max_value(export, "load1"),
            "mem_last": last_value(export, "mem_used_ratio"),
            "disk_last": last_value(export, "disk_used_ratio"),
            "disk_total": last_value(export, "disk_total_bytes"),
            "conntrack_max": max_value(export, "conntrack_used_ratio"),
            "stuck_last": last_value(export, "established_no_timer"),
            "stuck_max": max_value(export, "established_no_timer"),
            "updates": last_value(export, "pkg_updates"),
            "reboot": bool(last_value(export, "reboot_required", default=0)),
        })
    return rows


# ---------------------------------------------------------------- panel live


def gather_panel(config: dict, end_us: int):
    """The fleet as the panel sees it now, plus the client questions the
    letter asks: who is silent, who is near a limit or an expiry."""
    panel = config["panel"]
    connection = open_panel_db(panel["db"])
    data = {"nodes": [], "clients": [], "versions": {}}
    data["versions"]["master"] = {
        "panel": binary_version([panel["xui_bin"], "-v"]),
        "xray": binary_version([panel["xray_bin"], "version"]),
    }
    for node in db_nodes(connection):
        data["nodes"].append({
            "name": str(node.get("name") or node.get("remark") or ""),
            "online": node.get("status") == "online",
            "heartbeat": int(node.get("last_heartbeat") or 0),
            "latency_ms": node.get("latency_ms"),
            "cpu": node.get("cpu_pct"),
            "mem": node.get("mem_pct"),
            "panel_version": str(node.get("panel_version") or ""),
            "xray_version": str(node.get("xray_version") or ""),
        })
    now_ms = end_us // 1000
    for inbound in db_inbounds(connection):
        for client in inbound.get("clientStats") or []:
            up, down, last_online = client_traffic(client)
            total_cap = int(client.get("total") or 0)
            expiry_ms = int(client.get("expiryTime") or 0)
            used = up + down
            data["clients"].append({
                "label": client_label(client.get("email")),
                "inbound": str(inbound.get("remark") or ""),
                "enable": bool(client.get("enable", True)),
                "silent_days": (now_ms - last_online) / 86400000 if last_online else None,
                "cap_share": used / total_cap if total_cap else None,
                "expires_days": (expiry_ms - now_ms) / 86400000 if expiry_ms > 0 else None,
            })
    connection.close()
    return data


# ---------------------------------------------------------------- alerts


def collect_alerts(data: dict) -> list[str]:
    alerts = []
    if data.get("window_incomplete"):
        alerts.append("the master's collector has not caught up through the window; numbers are partial")
    for name, reason in data.get("unreachable", []):
        alerts.append(f"{name} did not answer the metrics pull ({reason}); its silence is not health")
    for name in data.get("stale", []):
        alerts.append(f"{name}'s collector stopped before the window ended; its numbers are partial")
    if data.get("panel_error"):
        alerts.append(f"the panel database did not answer: {data['panel_error']}")
    for row in data.get("health", []):
        if row["disk_last"] is not None and row["disk_last"] >= 0.85:
            left = (1 - row["disk_last"]) * (row["disk_total"] or 0)
            alerts.append(f"{row['node']}: disk {row['disk_last']:.0%} full ({format_bytes(left)} left)")
        if row["conntrack_max"] is not None and row["conntrack_max"] >= 0.8:
            alerts.append(f"{row['node']}: conntrack peaked at {row['conntrack_max']:.0%} of its limit")
        if row["stuck_last"] is not None and row["stuck_last"] >= 200:
            alerts.append(
                f"{row['node']}: {int(row['stuck_last'])} ESTABLISHED sockets with no timer armed"
                " — the shape of the timeout bug"
            )
        if row["reboot"]:
            alerts.append(f"{row['node']}: reboot required")
    for node in (data.get("panel") or {}).get("nodes", []):
        if not node["online"]:
            alerts.append(f"node {node['name']} is offline as the panel sees it")
    for timer, age_days in data.get("geodata_age", {}).items():
        if age_days is not None and age_days > 8:
            alerts.append(f"{timer}: geodata last refreshed {age_days:.0f} days ago")
    for client in (data.get("panel") or {}).get("clients", []):
        if client["cap_share"] is not None and client["cap_share"] >= 0.9 and client["enable"]:
            alerts.append(f"client {client['label']} is at {client['cap_share']:.0%} of its traffic limit")
        if client["expires_days"] is not None and 0 <= client["expires_days"] <= 7 and client["enable"]:
            alerts.append(f"client {client['label']} expires in {client['expires_days']:.0f} days")
    return alerts


# ---------------------------------------------------------------- charts
#
# Optional on purpose: a letter without charts is a letter, a letter with a
# dangling cid: is a broken one. Every chart function returns None when it has
# nothing to draw, and the caller attaches exactly what was drawn.


def _matplotlib():
    os.environ.setdefault("MPLCONFIGDIR", "/var/lib/skibidi-report/mpl")
    try:
        import matplotlib

        matplotlib.use("Agg")
        from matplotlib import pyplot as plt
    except ImportError:
        return None
    style = Path(os.environ.get("SKIBIDI_MPLSTYLE_FILE", "/etc/skibidi/ddlc.mplstyle"))
    if style.is_file():
        # The real theme, exactly as its own repo generated it: series order,
        # faces, grid and titles all come from the one file the deploy carried
        plt.style.use(os.fspath(style))
    font_file = Path(os.environ.get("SKIBIDI_CHART_FONT_FILE", "/etc/skibidi/chart-font.otf"))
    if font_file.is_file():
        # The data face the tables are set in, taught to matplotlib for this
        # process: axis text then matches the letter around the chart
        from matplotlib import font_manager

        font_manager.fontManager.addfont(os.fspath(font_file))
        family = font_manager.FontProperties(fname=os.fspath(font_file)).get_name()
        plt.rcParams["font.family"] = family
        # The pixel face has one weight; asking for bold just logs a fallback
        plt.rcParams["axes.titleweight"] = "normal"
    if not style.is_file():
        # A machine nobody themed still charts, in the neutral palette
        for key, value in {
            "axes.edgecolor": PALETTE["ash"],
            "axes.facecolor": PALETTE["paper"],
            "figure.facecolor": PALETTE["paper"],
            "savefig.facecolor": PALETTE["paper"],
            "text.color": PALETTE["ink"],
            "axes.labelcolor": PALETTE["ink"],
            "xtick.color": PALETTE["muted"],
            "ytick.color": PALETTE["muted"],
            "grid.color": PALETTE["ash"],
            "font.size": 9,
            "legend.frameon": False,
        }.items():
            plt.rcParams[key] = value
    return plt


def chart_cycle(plt) -> list:
    # The active style owns the series order — it carries the theme's own
    # colour-blindness guarantees, which a reshuffle here would silently void
    cycle = list(plt.rcParams["axes.prop_cycle"].by_key().get("color") or [])
    return cycle or PALETTE["cycle"]


def save_png(plt, figure, transparent=False) -> bytes:
    import io

    output = io.BytesIO()
    figure.savefig(output, format="png", dpi=140, transparent=transparent)
    plt.close(figure)
    return output.getvalue()


def scribble_bar(plt, share):
    """A meter drawn by hand, tidily: the xkcd wobble on two flat bars — the
    theme's accent over a track in the divider, mako's `progress-color over …`
    once more. Rendered as an image because inline CSS cannot scribble."""
    with plt.xkcd(scale=0.8, length=120, randomness=1.5):
        figure, axis = plt.subplots(figsize=(5.6, 0.34))
        axis.set_xlim(0, 1)
        axis.set_ylim(0, 1)
        axis.axis("off")
        axis.barh([0.5], [1.0], height=0.6,
                  color=PALETTE["divider"], edgecolor=PALETTE["divider"])
        if share > 0:
            axis.barh([0.5], [max(share, 0.03)], height=0.6,
                      color=PALETTE["accent"], edgecolor=PALETTE["accent"])
        figure.subplots_adjust(left=0.01, right=0.99, top=0.95, bottom=0.05)
        return save_png(plt, figure, transparent=True)


def tidy(axis):
    axis.spines["top"].set_visible(False)
    axis.spines["right"].set_visible(False)
    axis.grid(axis="y", linewidth=0.7)
    axis.set_axisbelow(True)


def chart_traffic(inbound_series):
    plt = _matplotlib()
    if not plt or not inbound_series or not any(t for _d, t in inbound_series):
        return None
    names = sorted({name for _day, totals in inbound_series for name in totals})
    figure, axis = plt.subplots(figsize=(10, 3.2))
    bottoms = [0.0] * len(inbound_series)
    labels = [day.strftime("%a %d") for day, _t in inbound_series]
    colors = chart_cycle(plt)
    for index, name in enumerate(names):
        values = [totals.get(name, 0) / 2**30 for _day, totals in inbound_series]
        axis.bar(labels, values, bottom=bottoms, label=name, color=colors[index % len(colors)])
        bottoms = [b + v for b, v in zip(bottoms, values)]
    axis.set_ylabel("GiB per day")
    axis.set_title("Traffic by inbound", loc="left")
    axis.legend(fontsize=8)
    tidy(axis)
    figure.tight_layout()
    return save_png(plt, figure)


def chart_security(bans_by_day, drops_by_day, days):
    plt = _matplotlib()
    if not plt or not days or (not any(bans_by_day.values()) and not any(drops_by_day.values())):
        return None
    figure, axis = plt.subplots(figsize=(10, 2.8))
    labels = [day.strftime("%a %d") for day in days]
    axis.bar(labels, [bans_by_day.get(day, 0) for day in days], label="fail2ban bans",
             color=PALETTE["warn"])
    axis.plot(labels, [drops_by_day.get(day, 0) for day in days], label="ufw drops",
              color=PALETTE["ink"], marker="o", linewidth=1.2)
    axis.set_title("Bans and drops", loc="left")
    axis.legend(fontsize=8)
    tidy(axis)
    figure.tight_layout()
    return save_png(plt, figure)


def chart_load(exports):
    plt = _matplotlib()
    rows = {name: series(export, "load1") for name, export in exports.items()}
    rows = {name: data for name, data in rows.items() if data}
    if not plt or not rows:
        return None
    figure, axis = plt.subplots(figsize=(10, 2.8))
    colors = chart_cycle(plt)
    for index, (name, data) in enumerate(sorted(rows.items())):
        stamps = [dt.datetime.fromtimestamp(ts / 1_000_000, dt.UTC) for ts, _d, _v in data]
        axis.plot(stamps, [v for _ts, _d, v in data], label=name,
                  color=colors[index % len(colors)], linewidth=1)
    axis.set_title("Load", loc="left")
    axis.legend(fontsize=8)
    tidy(axis)
    figure.tight_layout()
    return save_png(plt, figure)


def render_charts(data) -> dict[str, bytes]:
    charts = {}
    for name, png in (
        ("traffic", chart_traffic(data.get("inbound_series") or [])),
        ("security", chart_security(data.get("bans_by_day") or {}, data.get("drops_by_day") or {},
                                    data.get("days") or [])),
        ("load", chart_load(data.get("exports") or {})),
    ):
        if png:
            charts[name] = png
    return charts


# ---------------------------------------------------------------- rendering


# The layout follows the theme's own report stylesheet, spelled as inline
# styles because mail clients strip <style> blocks: prose on the ground
# colour, headings underlined by the divider, tables ruled between rows only,
# and nothing shaped like a card

def heading(title):
    # Doki has one weight; a synthetic bold smears it. Size and the divider
    # carry the hierarchy instead, and the theme's h2 says so
    return f'<h2 style="{style("h2")}">{html.escape(title)}</h2>'


def muted(text, size=13):
    return f'<p style="{style("sub", f"font-size:{size}px")}">{html.escape(text)}</p>'


def prose(text):
    return f'<p style="{style("p")}">{html.escape(text)}</p>'


def stat_tiles(pairs):
    """A handful of headline numbers is a KPI row, not a table: sentence-case
    label in the prose face, the value large in the data face. No synthetic
    bold — a pixel face carries hierarchy by size alone."""
    cells = "".join(
        f'<td style="{style("kpi-cell")}">'
        f'<div style="{style("kpi-label")}">{html.escape(str(label))}</div>'
        f'<div style="{style("kpi-value")}">{html.escape(str(value))}</div></td>'
        for label, value in pairs
    )
    return f'<table style="{style("kpi")}"><tr>{cells}</tr></table>'


def table(headers, rows, numeric=()):
    """The stylesheet's table: rules between rows only, no vertical lines, the
    header underlined a shade darker. Numeric columns are right-aligned in the
    data face, because digits only line up when every digit is the width of a
    zero, and a monospaced face gives that by construction."""
    def th_cell(index, header):
        align = "right" if index in numeric else "left"
        return f'<th style="{style("th", f"text-align:{align}")}">{html.escape(str(header))}</th>'

    def td_cell(index, cell):
        if str(cell).startswith("<div"):
            return f'<td style="{style("td-cell")}">{cell}</td>'
        if index in numeric:
            return f'<td style="{style("td-data", "text-align:right")}">{html.escape(str(cell))}</td>'
        return f'<td style="{style("td")}">{html.escape(str(cell))}</td>'

    th = "".join(th_cell(index, header) for index, header in enumerate(headers))
    body = "".join(
        "<tr>" + "".join(td_cell(index, cell) for index, cell in enumerate(row)) + "</tr>"
        for row in rows
    )
    return f'<table style="{style("table")}"><tr>{th}</tr>{body}</table>'


def bar(share, color, segments=16):
    """The CSS fallback meter, for a machine without matplotlib: discrete
    cells with a surface gap stretched across the column, the unfilled track
    in a light step of the theme."""
    filled = max(1, round(share * segments)) if share > 0 else 0
    cells = "".join(
        f'<td style="{style("meter-cell", "background:" + (color if index < filled else PALETTE["divider"]))}"></td>'
        for index in range(segments)
    )
    return f'<div><table style="{style("meter")}"><tr>{cells}</tr></table></div>'


def render_meters(data, charts) -> list:
    """Every meter image, drawn before any HTML exists: the attachments are
    decided in one place, and the HTML renderer stays a pure reader of them.
    Returns one table cell per client — the scribbled image where charts
    render at all, the segmented CSS meter where they cannot."""
    deltas = (data.get("client_deltas") or [])[:10]
    if not deltas:
        return []
    top = max(delta for _label, delta in deltas) or 1
    plt = _matplotlib()
    cells = []
    for index, (_label, delta) in enumerate(deltas):
        share = delta / top
        if plt is None:
            cells.append(bar(share, PALETTE["accent"]))
        else:
            charts[f"meter-{index}"] = scribble_bar(plt, share)
            cells.append(f'<div><img src="cid:skibidi-meter-{index}" alt="" '
                         'style="width:100%;max-width:320px;height:auto;display:block"></div>')
    return cells


def chart_image(name):
    return f'<img src="cid:skibidi-{name}" alt="{name} chart" style="{style("image")}">'


def inform_dialog(title, items):
    # The game's "Just Monika." pop-up, not a stripe-edged callout: a pale
    # ground in a thick frame, everything centred, the ink doing the talking.
    # Unthemed, the warn colour still frames it, so it never reads as prose
    lines = "".join(f'<li style="{style("inform-item")}">{html.escape(item)}</li>' for item in items)
    frame = "" if THEME else f'border:2px solid {PALETTE["warn"]};padding:12px'
    return (
        f'<div style="{style("inform", frame)}">'
        f'<div style="{style("inform-title")}">{html.escape(title)}</div>'
        f'<ul style="{style("inform-list")}">{lines}</ul></div>'
    )


def overview_pairs(data):
    total = sum(delta for _label, delta in data.get("client_deltas") or [])
    reachable = len(data.get("exports") or {})
    fleet = reachable + len(data.get("unreachable") or [])
    pairs = [
        ("traffic", format_bytes(total) if total else "no data"),
        ("nodes answering", f"{reachable}/{fleet}"),
        ("alerts", len(data.get("alerts") or [])),
    ]
    bans = sum((data.get("bans_by_day") or {}).values())
    pairs.append(("bans", bans))
    return pairs


def render_html(data, charts):
    sections = []
    alerts = data.get("alerts") or []
    if alerts:
        sections.append(inform_dialog("Needs attention", alerts))

    sections.append(heading("Overview"))
    sections.append(stat_tiles(overview_pairs(data)))

    traffic_parts = []
    if "traffic" in charts:
        traffic_parts.append(chart_image("traffic"))
    client_deltas = data.get("client_deltas") or []
    if client_deltas:
        meters = data.get("meter_cells") or []
        top = max(delta for _l, delta in client_deltas) or 1
        traffic_parts.append(table(
            ["client", "", "over the week"],
            [[label,
              meters[index] if index < len(meters) else bar(delta / top, PALETTE["accent"]),
              format_bytes(delta)]
             for index, (label, delta) in enumerate(client_deltas[:10])],
            numeric=(2,),
        ))
    silent = [c for c in (data.get("panel") or {}).get("clients", [])
              if c["enable"] and c["silent_days"] is not None and c["silent_days"] >= 30]
    if silent:
        names = ", ".join(sorted(c["label"] for c in silent))
        traffic_parts.append(prose(f"Silent for a month or more: {names}"))
    if traffic_parts:
        sections.append(heading("Traffic and clients"))
        sections.extend(traffic_parts)

    health = data.get("health") or []
    if health:
        sections.append(heading("System health"))
        if "load" in charts:
            sections.append(chart_image("load"))
        rows = []
        for row in health:
            updates = f"{int(row['updates'])}" if row["updates"] is not None else "?"
            if row["reboot"]:
                updates += " · reboot required"
            rows.append([
                row["node"],
                f"{row['uptime'] / 86400:.0f}d" if row["uptime"] is not None else "?",
                f"{row['load_max']:.2f}" if row["load_max"] is not None else "?",
                f"{row['disk_last']:.0%}" if row["disk_last"] is not None else "?",
                f"{row['conntrack_max']:.1%}" if row["conntrack_max"] is not None else "?",
                f"{int(row['stuck_last'])}" if row["stuck_last"] is not None else "?",
                updates,
            ])
        sections.append(table(
            ["node", "up", "load peak", "disk", "conntrack peak", "untimed sockets", "updates"],
            rows, numeric=(1, 2, 3, 4, 5, 6)))

    security_parts = []
    if "security" in charts:
        security_parts.append(chart_image("security"))
    ssh_attempts = data.get("ssh_attempts") or {}
    if ssh_attempts:
        security_parts.append(table(
            ["node", "failed logins"], [list(pair) for pair in sorted(ssh_attempts.items())],
            numeric=(1,)))
    if security_parts:
        sections.append(heading("Security"))
        sections.extend(security_parts)

    fleet_parts = []
    nodes = (data.get("panel") or {}).get("nodes", [])
    if nodes:
        fleet_parts.append(table(
            ["node", "state", "latency", "xray", "panel"],
            [[node["name"],
              "online" if node["online"] else "OFFLINE",
              f"{node['latency_ms']} ms" if node["latency_ms"] is not None else "?",
              node["xray_version"] or "?",
              node["panel_version"] or "?"] for node in nodes],
            numeric=(2,),
        ))
    restarts = data.get("unit_restart_deltas") or []
    if restarts:
        fleet_parts.append(table(["unit", "restarts"],
                                 [[unit, delta] for unit, delta in restarts],
                                 numeric=(1,)))
    versions = (data.get("panel") or {}).get("versions", {})
    if versions.get("master", {}).get("panel"):
        master = versions["master"]
        fleet_parts.append(muted(
            f"master: panel {master['panel']}"
            + (f", xray {master['xray']}" if master["xray"] else "")))
    if fleet_parts:
        sections.append(heading("Fleet state"))
        sections.extend(fleet_parts)

    changes = data.get("changes") or []
    if changes:
        sections.append(heading("What changed this week"))
        items = "".join(
            f'<li style="{style("item")}">{html.escape(line)}</li>' for line in changes)
        sections.append(f'<ul style="{style("list")}">{items}</ul>')

    start, end = data["start"], data["end"]
    return (
        f'<div style="{style("page")}">'
        f'<div style="{style("column")}">'
        f'<h1 style="{style("h1")}">Weekly VPN report</h1>'
        + muted(f"{start:%Y-%m-%d %H:%M} — {end:%Y-%m-%d %H:%M} · {data['timezone']}")
        + "".join(sections)
        + f'<div style="{style("divider", "border-top:2px solid " + PALETTE["divider"])}"></div>'
        + muted("skibidi-report · the letter always goes out; partial numbers are named as partial", 12)
        + "</div></div>"
    )


def render_text(data):
    lines = [f"Weekly VPN report, {data['start']:%Y-%m-%d} — {data['end']:%Y-%m-%d}", ""]
    for alert in data.get("alerts") or []:
        lines.append(f"[!] {alert}")
    if data.get("alerts"):
        lines.append("")
    for label, value in overview_pairs(data):
        lines.append(f"{label}: {value}")
    lines.append("")
    for label, delta in (data.get("client_deltas") or [])[:10]:
        lines.append(f"  {label}: {format_bytes(delta)}")
    for row in data.get("health") or []:
        disk = f"{row['disk_last']:.0%}" if row["disk_last"] is not None else "?"
        lines.append(f"{row['node']}: disk {disk}, "
                     f"{int(row['updates'] or 0)} updates pending")
    for line in data.get("changes") or []:
        lines.append(f"changed: {line}")
    return "\n".join(lines) + "\n"


def build_message(data, sender, recipient):
    charts = render_charts(data)
    data["meter_cells"] = render_meters(data, charts)
    message = EmailMessage()
    message["From"] = f"VPN fleet <{sender}>"
    message["To"] = recipient
    prefix = "[!] " if data.get("alerts") else ""
    message["Subject"] = f"{prefix}Weekly VPN report: {data['end']:%Y-%m-%d}"
    message["Auto-Submitted"] = "auto-generated"
    # Journal lines and client labels are arbitrary bytes; utf-8 with 8bit is
    # what keeps a Russian remark from breaking the part
    message.set_content(render_text(data), charset="utf-8", cte="8bit")
    message.add_alternative(render_html(data, charts), subtype="html", charset="utf-8")
    payload = message.get_payload()
    assert isinstance(payload, list)
    html_part = payload[-1]
    assert isinstance(html_part, EmailMessage)
    for name, png in charts.items():
        html_part.add_related(
            png,
            maintype="image",
            subtype="png",
            cid=f"<skibidi-{name}>",
            disposition="inline",
            filename=f"skibidi-{name}.png",
        )
    return message


# ---------------------------------------------------------------- assembly


def assemble(config: dict, now=None) -> dict:
    report = config["report"]
    zone_name = report.get("timezone", "Europe/Moscow")
    zone = ZoneInfo(zone_name)
    start_us, end_us = report_window(
        now, zone_name, int(report.get("hour", 9)), int(report.get("weekday", 0))
    )
    start = dt.datetime.fromtimestamp(start_us / 1_000_000, dt.UTC).astimezone(zone)
    end = dt.datetime.fromtimestamp(end_us / 1_000_000, dt.UTC).astimezone(zone)
    master_name = report.get("master_name", "master")

    # The freshness contract: wait briefly for the local collector to cross
    # the window's end, then report anyway and say the numbers are partial.
    # The letter always goes out — silence is reserved for the reporting
    # itself being broken.
    deadline = time.monotonic() + int(report.get("catchup_seconds", 120))
    window_incomplete = not wait_for_collector(config, master_name, end_us, deadline)

    exports, unreachable, stale = gather_metrics(config, start_us, end_us)

    data = {
        "start": start,
        "end": end,
        "timezone": zone_name,
        "days": [start.date() + dt.timedelta(days=offset) for offset in range(7)],
        "exports": exports,
        "unreachable": unreachable,
        "stale": stale,
        "window_incomplete": window_incomplete,
        "health": health_rows(exports),
    }

    bans, drops, attempts, restarts, geodata = {}, {}, {}, [], {}
    for name, export in exports.items():
        for day, value in daily_sums(export, "ufw_drops", zone).items():
            drops[day] = drops.get(day, 0) + value
        # Bans are cumulative totals sampled, not events; the honest weekly
        # number is a sum of clamped steps, and per-day resolution comes from
        # where each step landed in the samples
        for jail in {det for _ts, det, _v in series(export, "f2b_banned_total")}:
            rows = series(export, "f2b_banned_total", jail)
            previous = None
            for ts, _det, value in rows:
                if previous is not None:
                    step = clamped_delta(int(value), int(previous))
                    if step:
                        day = dt.datetime.fromtimestamp(ts / 1_000_000, dt.UTC).astimezone(zone).date()
                        bans[day] = bans.get(day, 0) + step
                previous = value
        failed = counter_week_delta(export, "f2b_failed_total", "sshd")
        if failed:
            attempts[name] = failed
        for unit in {det for _ts, det, _v in series(export, "unit_restarts")}:
            delta = counter_week_delta(export, "unit_restarts", unit)
            if delta:
                restarts.append((f"{name}/{unit}", delta))
        fired = last_value(export, "timer_last_fired", "xray-geodata-update.timer")
        geodata[name] = (end_us / 1_000_000 - fired) / 86400 if fired else None
    data["bans_by_day"] = bans
    data["drops_by_day"] = drops
    data["ssh_attempts"] = attempts
    data["unit_restart_deltas"] = sorted(restarts, key=lambda pair: -pair[1])
    data["geodata_age"] = geodata

    state_dir = config["paths"]["state_dir"]
    snapshots = load_snapshots(state_dir, start.date(), end.date())
    data["inbound_series"] = daily_inbound_series(snapshots)
    data["client_deltas"] = weekly_client_deltas(snapshots)
    first_day, last_day = (min(snapshots), max(snapshots)) if len(snapshots) >= 2 else (None, None)
    data["changes"] = structure_diff(
        snapshots[first_day]["structure"] if first_day else None,
        snapshots[last_day]["structure"] if last_day else None,
    )

    try:
        data["panel"] = gather_panel(config, end_us)
    except (PanelError, sqlite3.Error, json.JSONDecodeError, OSError) as error:
        data["panel"] = None
        data["panel_error"] = str(error)

    data["alerts"] = collect_alerts(data)
    return data


def send(config: dict, print_only: bool = False) -> int:
    report = config["report"]
    sender = report.get("sender") or f"skibidi-vpn@{os.uname().nodename}"
    data = assemble(config)
    message = build_message(data, sender, report["to"])
    if print_only:
        sys.stdout.buffer.write(message.as_bytes())
        return 0
    subprocess.run(
        [config["paths"]["sendmail"], "-t"], input=message.as_bytes(), check=True
    )
    return 0


def main(argv: list[str]) -> int:
    config = load_config()
    if argv[:1] == ["snapshot"]:
        take_snapshot(config)
        return 0
    if argv[:1] == ["send"]:
        return send(config, print_only="--print" in argv[1:])
    if argv[:1] == ["probe"]:
        return probe(config)
    print("usage: skibidi-report snapshot | send [--print] | probe", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
