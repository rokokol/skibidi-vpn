#!/usr/bin/env python3
"""The weekly letter. One message from the master, covering the whole fleet.

Everything here reads — the panel's API, the fleet's metric stores over a
key that can only ask for metrics, and this host's own daily snapshots — and
writes one multipart message.

Two rules the layout hangs on, both inherited from the mail host's report. A
section with nothing to say is omitted entirely, in text and HTML alike — but
the letter itself is always sent, so a missing Monday letter can only ever mean
the reporting is broken. And there is no permanent status banner: an alert
block exists only when something is wrong, and it also prefixes the subject,
so trouble is visible in a notification without opening anything.

The panel token is minted at startup by the panel's own CLI and lives only in
this process: nothing on disk holds a credential, and reissuing under the
cli-fallback name invalidates the previous run's token by design.
"""

from __future__ import annotations

import datetime as dt
import html
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
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

# The neutral fallback; the deployed master overrides it with the DDLC palette
# the flake is locked to, delivered as /etc/skibidi/palette.json at deploy time
PALETTE_DEFAULTS = {
    "paper": "#f6f7f9",
    "ink": "#1f2430",
    "muted": "#5b6472",
    "accent": "#3b6ea5",
    "ok": "#3f7d4e",
    "warn": "#b3423a",
    "ash": "#d8dce3",
    "blush": "#f9e9e7",
}

# The theme's own series order, kept as-is because it is a safety mechanism
# rather than a taste: adjacent entries are what a stacked bar puts side by
# side, and each neighbour pair clears deuteranopia in the palette's tests
THEME_CYCLE = ("plum", "bow", "rule", "monikaEye", "yuri")

# What each semantic slot means in the theme's vocabulary
THEME_ROLES = {
    "paper": "paper",
    "ink": "ink",
    "muted": "jacket",
    "ash": "ash",
    "blush": "blush",
    "warn": "bow",
    "accent": "plum",
    "ok": "monikaEye",
}


def load_palette(named: dict | None = None) -> dict:
    """Semantic slots resolved against the theme, wherever the theme is.

    REPORT_PALETTE in the environment wins (the mail host's convention), then
    the file the deploy carried over, then the neutral defaults — a report on
    a machine nobody themed still renders.
    """
    if named is None:
        raw = os.environ.get("REPORT_PALETTE", "")
        if not raw:
            try:
                raw = Path(
                    os.environ.get("SKIBIDI_PALETTE_FILE", "/etc/skibidi/palette.json")
                ).read_text()
            except OSError:
                raw = ""
        try:
            named = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            named = {}
    named = named or {}
    palette: dict = dict(PALETTE_DEFAULTS)
    for slot, theme_name in THEME_ROLES.items():
        if theme_name in named:
            palette[slot] = named[theme_name]
    if all(name in named for name in THEME_CYCLE):
        palette["cycle"] = [named[name] for name in THEME_CYCLE]
    else:
        palette["cycle"] = [palette[slot] for slot in ("accent", "warn", "muted", "ok", "ink")]
    return palette


PALETTE = load_palette()


# ---------------------------------------------------------------- config


def load_config(path: str | None = None) -> dict:
    file = Path(path or os.environ.get("SKIBIDI_REPORT_CONFIG", "/etc/skibidi/report.toml"))
    with file.open("rb") as handle:
        config = tomllib.load(handle)
    config.setdefault("report", {})
    config.setdefault("panel", {})
    config.setdefault("paths", {})
    config.setdefault("nodes", [])
    paths = config["paths"]
    paths.setdefault("state_dir", "/var/lib/skibidi-report")
    paths.setdefault("metrics", "/usr/local/sbin/skibidi-metrics")
    paths.setdefault("sendmail", "/usr/sbin/sendmail")
    paths.setdefault("ssh_key", "/root/.ssh/skibidi-report")
    config["panel"].setdefault("xui_cli", "/usr/local/x-ui/x-ui")
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


def mask_label(value) -> str:
    """The skill's degradation for client labels: personal data, but also the
    only handle an operator has on a row, so a stub rather than nothing."""
    text = str(value or "")
    if len(text) <= 2:
        return "*" * len(text)
    keep = 2 if len(text) <= 5 else 3
    return f"{text[:keep]}{'*' * (len(text) - keep)}"


def format_bytes(count) -> str:
    count = float(count)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if count < 1024 or unit == "TiB":
            return f"{count:.1f} {unit}" if unit != "B" else f"{int(count)} B"
        count /= 1024
    return f"{count:.1f} TiB"


# ---------------------------------------------------------------- panel


class PanelError(Exception):
    pass


def mint_token(xui_cli: str) -> str:
    """Ask the panel's own CLI for a fresh API token.

    The database stores only a hash, so there is nothing to read back later:
    the plaintext exists exactly once, here, and stays in this process. Each
    call reissues under the cli-fallback name, which this report owns on the
    master — anything else binding to that name would be knocked out weekly.
    """
    result = subprocess.run(
        [xui_cli, "setting", "-getApiToken"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode != 0:
        raise PanelError(f"x-ui CLI refused: {result.stderr.strip() or result.returncode}")
    candidates = [
        word for word in result.stdout.split()
        if len(word) >= 16 and re.fullmatch(r"[A-Za-z0-9._=+/-]+", word)
    ]
    if not candidates:
        raise PanelError("x-ui CLI printed nothing that looks like a token")
    return candidates[-1]


class Panel:
    """The slice of the skill's API client this report needs.

    Same two panel behaviours shape it: an unauthenticated request answers 404
    unless it announces itself as XHR, and an unserved path answers success
    with an empty body — so the header is always sent and empty is an error.
    """

    def __init__(self, url: str, token: str, verify_tls: bool = False):
        self.base = url.rstrip("/") + "/panel/api"
        self.token = token
        self.context = (
            ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
        )

    def request(self, method: str, path: str):
        request = urllib.request.Request(
            f"{self.base}/{path.lstrip('/')}",
            headers={
                "Authorization": f"Bearer {self.token}",
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json",
                "User-Agent": "skibidi-report",
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=30, context=self.context) as response:
                raw = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            raw, status = error.read(), error.code
        except urllib.error.URLError as error:
            raise PanelError(f"cannot reach the panel: {error.reason}") from error
        if status >= 400 or not raw:
            raise PanelError(f"{method} {path}: HTTP {status}, body {len(raw)} bytes")
        payload = json.loads(raw)
        if isinstance(payload, dict) and "success" in payload:
            if not payload.get("success"):
                raise PanelError(f"{method} {path}: {payload.get('msg') or 'refused'}")
            return payload.get("obj")
        return payload

    def get(self, path: str):
        return self.request("GET", path)

    def post(self, path: str):
        return self.request("POST", path)


def client_traffic(client: dict) -> tuple[int, int, int]:
    """up, down, lastOnline — wherever this panel version put them.

    Traffic lives in a nested `traffic` object rather than on the client in
    the fleet's version; older shapes carry it flat. Reading both keeps a
    panel upgrade from silently zeroing the report's numbers.
    """
    source = client.get("traffic") if isinstance(client.get("traffic"), dict) else client
    return (
        int(source.get("up") or 0),
        int(source.get("down") or 0),
        int(source.get("lastOnline") or client.get("lastOnline") or 0),
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
        clients.append(mask_label(client.get("email")))
    return {
        "key": f"{inbound.get('nodeId') or inbound.get('node_id') or 0}"
               f"/{inbound.get('protocol')}/{inbound.get('port')}",
        "remark": str(inbound.get("remark") or ""),
        "enable": bool(inbound.get("enable")),
        "clients": sorted(clients),
    }


def sanitise_routing(panel: Panel) -> list:
    """Routing rules, unwrapped from the double envelope the panel serves.

    POST with the trailing slash — without it the panel answers 307, which
    urllib does not follow for POST. The payload is a JSON string holding
    xraySetting, which may itself be a string again.
    """
    raw = panel.post("xray/")
    for _ in range(2):
        if isinstance(raw, str):
            raw = json.loads(raw)
    setting = raw.get("xraySetting") if isinstance(raw, dict) else None
    for _ in range(2):
        if isinstance(setting, str):
            setting = json.loads(setting)
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
    token = mint_token(config["panel"]["xui_cli"])
    panel = Panel(config["panel"]["url"], token, config["panel"].get("verify_tls", False))

    inbounds = panel.get("inbounds/list") or []
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
            label = mask_label(client.get("email"))
            traffic["clients"][label] = {
                "up": up,
                "down": down,
                "total": int(client.get("total") or 0),
                "expiry": int(client.get("expiryTime") or 0),
                "enable": bool(client.get("enable", True)),
                "last_online": last_online,
            }
    try:
        structure["routing"] = sanitise_routing(panel)
    except (PanelError, json.JSONDecodeError, AttributeError) as error:
        print(f"routing snapshot: {error}", file=sys.stderr)

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


def pull_node(config: dict, node: dict, start_us: int, end_us: int) -> dict:
    argv = [
        "ssh", "-i", config["paths"]["ssh_key"],
        "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new",
        f"root@{node['host']}",
        f"skibidi-metrics export --since {start_us} --until {end_us}",
    ]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
    if result.returncode != 0:
        raise StaleWindow(result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "no answer")
    return json.loads(result.stdout)


def local_export(config: dict, start_us: int, end_us: int) -> dict:
    result = subprocess.run(
        [config["paths"]["metrics"], "export", "--since", str(start_us), "--until", str(end_us)],
        capture_output=True, text=True, timeout=60, check=False,
    )
    if result.returncode != 0:
        raise StaleWindow(result.stderr.strip() or "local metrics store did not answer")
    return json.loads(result.stdout)


def gather_metrics(config: dict, start_us: int, end_us: int, master_name: str):
    """Every node's window, with absence recorded rather than smoothed over.

    A node that was down looks exactly like a quiet one in every counter it
    failed to deliver, so the letter says which nodes did not answer instead
    of letting their silence read as health.
    """
    exports, unreachable, stale = {}, [], []
    try:
        exports[master_name] = local_export(config, start_us, end_us)
    except (StaleWindow, json.JSONDecodeError, OSError) as error:
        unreachable.append((master_name, str(error)))
    for node in config["nodes"]:
        try:
            exports[node["name"]] = pull_node(config, node, start_us, end_us)
        except (StaleWindow, json.JSONDecodeError, subprocess.TimeoutExpired, OSError) as error:
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
    token = mint_token(config["panel"]["xui_cli"])
    panel = Panel(config["panel"]["url"], token, config["panel"].get("verify_tls", False))
    data = {"nodes": [], "clients": [], "versions": {}}
    status = panel.get("server/status") or {}
    data["versions"]["master"] = {
        "panel": str(status.get("appVersion") or status.get("version") or ""),
        "xray": str((status.get("xray") or {}).get("version") or ""),
    }
    try:
        listed = panel.get("nodes/list") or []
    except PanelError:
        listed = []
    for node in listed:
        data["nodes"].append({
            "name": str(node.get("name") or node.get("remark") or node.get("id")),
            "online": bool(node.get("online") or node.get("status") in (1, "online")),
            "heartbeat": int(node.get("lastHeartbeat") or 0),
            "latency_ms": node.get("latencyMs"),
            "cpu": node.get("cpuPct"),
            "mem": node.get("memPct"),
            "panel_version": str(node.get("panelVersion") or ""),
            "xray_version": str(node.get("xrayVersion") or ""),
        })
    now_ms = end_us // 1000
    for inbound in panel.get("inbounds/list") or []:
        for client in inbound.get("clientStats") or []:
            up, down, last_online = client_traffic(client)
            total_cap = int(client.get("total") or 0)
            expiry_ms = int(client.get("expiryTime") or 0)
            used = int(client.get("up") or up) + int(client.get("down") or down)
            data["clients"].append({
                "label": mask_label(client.get("email")),
                "inbound": str(inbound.get("remark") or ""),
                "enable": bool(client.get("enable", True)),
                "silent_days": (now_ms - last_online) / 86400000 if last_online else None,
                "cap_share": used / total_cap if total_cap else None,
                "expires_days": (expiry_ms - now_ms) / 86400000 if expiry_ms > 0 else None,
            })
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
        alerts.append(f"the panel did not answer: {data['panel_error']}")
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
    except ImportError:
        return None


def save_png(plt, figure) -> bytes:
    import io

    output = io.BytesIO()
    figure.savefig(output, format="png", dpi=140)
    plt.close(figure)
    return output.getvalue()


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
    colors = PALETTE["cycle"]
    for index, name in enumerate(names):
        values = [totals.get(name, 0) / 2**30 for _day, totals in inbound_series]
        axis.bar(labels, values, bottom=bottoms, label=name, color=colors[index % len(colors)])
        bottoms = [b + v for b, v in zip(bottoms, values)]
    axis.set_ylabel("GiB per day")
    axis.set_title("Traffic by inbound", loc="left", fontweight="bold")
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
    axis.set_title("Bans and drops", loc="left", fontweight="bold")
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
    colors = PALETTE["cycle"]
    for index, (name, data) in enumerate(sorted(rows.items())):
        stamps = [dt.datetime.fromtimestamp(ts / 1_000_000, dt.UTC) for ts, _d, _v in data]
        axis.plot(stamps, [v for _ts, _d, v in data], label=name,
                  color=colors[index % len(colors)], linewidth=1)
    axis.set_title("Load", loc="left", fontweight="bold")
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


def bar_rows(rows, color, unit="", value_format=str):
    top = max((count for _label, count in rows), default=0) or 1
    cells = []
    for label, count in rows:
        share = count / top
        cells.append(
            "<tr>"
            f'<td style="padding:3px 10px 3px 0;color:{PALETTE["ink"]};'
            f'font-size:13px;white-space:nowrap">{html.escape(str(label))}</td>'
            f'<td style="padding:3px 0;width:55%"><div style="background:{color};'
            f'height:10px;border-radius:3px;width:{max(2, round(share * 100))}%"></div></td>'
            f'<td style="padding:3px 0 3px 10px;color:{PALETTE["ink"]};font-size:13px;'
            f'text-align:right">{html.escape(value_format(count))}{unit}</td>'
            "</tr>"
        )
    return '<table style="border-collapse:collapse;width:100%">' + "".join(cells) + "</table>"


def card(title, body):
    return (
        f'<div style="background:{PALETTE["paper"]};border-radius:10px;'
        'padding:18px 20px;margin:0 0 14px">'
        f'<h2 style="margin:0 0 10px;font-size:15px;color:{PALETTE["ink"]}">'
        f"{html.escape(title)}</h2>{body}</div>"
    )


def chart_image(name):
    return (
        f'<img src="cid:skibidi-{name}" alt="{name} chart" '
        'style="max-width:100%;height:auto;display:block;margin:0 0 10px">'
    )


def kpi_row(pairs):
    cells = "".join(
        '<td style="text-align:center;padding:10px 6px">'
        f'<div style="font-size:24px;font-weight:bold;color:{PALETTE["ink"]}">'
        f"{html.escape(str(value))}</div>"
        f'<div style="font-size:11px;color:{PALETTE["muted"]};'
        f'text-transform:uppercase;letter-spacing:0.5px">{html.escape(label)}</div></td>'
        for label, value in pairs
    )
    return '<table style="border-collapse:collapse;width:100%"><tr>' + cells + "</tr></table>"


def paragraph(text):
    return f'<p style="margin:8px 0 0;font-size:13px;color:{PALETTE["ink"]}">{html.escape(text)}</p>'


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
        items = "".join(f"<li>{html.escape(alert)}</li>" for alert in alerts)
        sections.append(
            f'<div style="background:{PALETTE["blush"]};border-left:6px solid '
            f'{PALETTE["warn"]};border-radius:6px;padding:14px 18px;margin:0 0 14px;'
            f'color:{PALETTE["warn"]}"><strong>Needs attention</strong>'
            f'<ul style="margin:8px 0 0;padding-left:20px">{items}</ul></div>'
        )

    sections.append(card("Overview", kpi_row(overview_pairs(data))))

    traffic_parts = []
    if "traffic" in charts:
        traffic_parts.append(chart_image("traffic"))
    client_deltas = data.get("client_deltas") or []
    if client_deltas:
        traffic_parts.append(bar_rows(client_deltas[:10], PALETTE["accent"],
                                      value_format=format_bytes))
    silent = [c for c in (data.get("panel") or {}).get("clients", [])
              if c["enable"] and c["silent_days"] is not None and c["silent_days"] >= 30]
    if silent:
        names = ", ".join(sorted(c["label"] for c in silent))
        traffic_parts.append(paragraph(f"Silent for a month or more: {names}"))
    if traffic_parts:
        sections.append(card("Traffic and clients", "".join(traffic_parts)))

    health = data.get("health") or []
    if health:
        rows = []
        for row in health:
            notes = []
            if row["uptime"] is not None:
                notes.append(f"up {row['uptime'] / 86400:.0f}d")
            if row["load_max"] is not None:
                notes.append(f"load peak {row['load_max']:.2f}")
            if row["disk_last"] is not None:
                notes.append(f"disk {row['disk_last']:.0%}")
            if row["conntrack_max"] is not None:
                notes.append(f"conntrack peak {row['conntrack_max']:.1%}")
            if row["stuck_last"] is not None:
                notes.append(f"{int(row['stuck_last'])} untimed sockets")
            if row["updates"] is not None:
                notes.append(f"{int(row['updates'])} updates pending")
            if row["reboot"]:
                notes.append("reboot required")
            rows.append(paragraph(f"{row['node']}: {', '.join(notes)}"))
        body = "".join(rows)
        if "load" in charts:
            body = chart_image("load") + body
        sections.append(card("System health", body))

    security_parts = []
    if "security" in charts:
        security_parts.append(chart_image("security"))
    ssh_attempts = data.get("ssh_attempts") or {}
    if ssh_attempts:
        security_parts.append(bar_rows(sorted(ssh_attempts.items()), PALETTE["warn"]))
    if security_parts:
        sections.append(card("Security", "".join(security_parts)))

    fleet_parts = []
    for node in (data.get("panel") or {}).get("nodes", []):
        state = "online" if node["online"] else "OFFLINE"
        detail = []
        if node["latency_ms"] is not None:
            detail.append(f"{node['latency_ms']} ms")
        if node["xray_version"]:
            detail.append(f"xray {node['xray_version']}")
        if node["panel_version"]:
            detail.append(f"panel {node['panel_version']}")
        fleet_parts.append(paragraph(f"{node['name']}: {state}" +
                                     (f" ({', '.join(detail)})" if detail else "")))
    restarts = data.get("unit_restart_deltas") or []
    if restarts:
        fleet_parts.append(bar_rows(restarts, PALETTE["muted"], unit=" restarts"))
    versions = (data.get("panel") or {}).get("versions", {})
    if versions.get("master", {}).get("panel"):
        master = versions["master"]
        fleet_parts.append(paragraph(
            f"master: panel {master['panel']}" + (f", xray {master['xray']}" if master["xray"] else "")))
    if fleet_parts:
        sections.append(card("Fleet state", "".join(fleet_parts)))

    changes = data.get("changes") or []
    if changes:
        items = "".join(f"<li>{html.escape(line)}</li>" for line in changes)
        sections.append(card(
            "What changed this week",
            f'<ul style="margin:0;padding-left:20px;font-size:13px;'
            f'color:{PALETTE["ink"]}">{items}</ul>'))

    start, end = data["start"], data["end"]
    return (
        f'<div style="background:{PALETTE["ash"]};padding:18px;'
        'font-family:-apple-system,Segoe UI,Roboto,sans-serif">'
        f'<div style="max-width:720px;margin:0 auto">'
        f'<h1 style="font-size:19px;color:{PALETTE["ink"]};margin:0 0 4px">Weekly VPN report</h1>'
        f'<p style="margin:0 0 14px;font-size:12px;color:{PALETTE["muted"]}">'
        f"{start:%Y-%m-%d %H:%M} — {end:%Y-%m-%d %H:%M} {html.escape(data['timezone'])}</p>"
        + "".join(sections) +
        "</div></div>"
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
    window_incomplete = True
    while time.monotonic() < deadline:
        try:
            probe = local_export(config, end_us - 1, end_us)
            if probe.get("collected_through_us", 0) >= end_us:
                window_incomplete = False
                break
        except (StaleWindow, json.JSONDecodeError, OSError):
            pass
        time.sleep(5)

    exports, unreachable, stale = gather_metrics(config, start_us, end_us, master_name)

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
    except (PanelError, subprocess.TimeoutExpired, OSError) as error:
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
    print("usage: skibidi-report snapshot | send [--print]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
