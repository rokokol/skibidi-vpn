"""What counts as a problem that is still open. This file is the only list.

Two mechanisms report trouble. `skibidi-check` fails a node within half an
hour for what must work right now, and mails at once. The rules here are the
other half: the open items that can wait for the daily mail, read from the
numbers a node samples and from the panel on the master. The daily check
puts both into one mail, so a fact that `skibidi-check` already tests (the
conntrack table, a service that is down) has no rule here.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

DISK_FULL = 0.85
STUCK_SOCKETS = 200
GEODATA_DAYS = 8
CAP_SHARE = 0.9
EXPIRY_DAYS = 7
COLLECTOR_LAG_SECONDS = 30 * 60

GEODATA_TIMER = "xray-geodata-update.timer"


def format_bytes(count) -> str:
    count = float(count)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if count < 1024 or unit == "TiB":
            return f"{count:.1f} {unit}" if unit != "B" else f"{int(count)} B"
        count /= 1024
    return f"{count:.1f} TiB"


SUMMARY_LIMIT = 120


def cause_key(text: str) -> str:
    """A cause as a label value the station can match on: letters, digits,
    dots, underscores and hyphens, and never empty"""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text.strip()).strip("-") or "unknown"


def summary(message: str) -> str:
    """One short plain line for an alert subject: the message up to its first
    semicolon, where the checks put the consequence, cut to one line"""
    first = " ".join(message.split(";")[0].split())
    return first[:SUMMARY_LIMIT]


def check_records(record, max_age_hours: float) -> list[tuple[str, str]]:
    """What the last run of skibidi-check left open, as (cause, message), from
    the file it records, one `cause<TAB>message` line per failure. A result
    nobody has refreshed is not a result: its old failures would be replayed
    for as long as the timer stays dead, and that dead timer is the one
    problem to report. A missing record is another problem, with another
    cause, because its remedy is another. The daily list and the push to the
    station both read the urgent problems here"""
    record = Path(record)
    try:
        age = time.time() - record.stat().st_mtime
        lines = record.read_text().splitlines()
    except OSError:
        return [("check.record-missing", "skibidi-check has not recorded a result on this node")]
    if age > max_age_hours * 3600:
        return [("check.record-stale",
                 f"skibidi-check has not recorded a result for {age / 3600:.0f} hours")]
    found = []
    for line in lines:
        if not line.strip():
            continue
        # A record an older check wrote has no cause; its words make one
        cause, tab, message = line.partition("\t")
        found.append((cause_key(cause), message) if tab else (cause_key(line[:60]), line))
    return found


def check_failures(record, max_age_hours: float) -> list[str]:
    return [message for _cause, message in check_records(record, max_age_hours)]


def node_problems(latest: dict, health: dict, now: float) -> list[str]:
    """Open items of one node: its newest value of each series, as
    {(metric, detail): value}, and what /v1/health says of its collector"""
    found = []
    through = health.get("collected_through_us")
    if through is None:
        found.append("the metrics collector has not finished a run")
    elif now - through / 1_000_000 > COLLECTOR_LAG_SECONDS:
        hours = (now - through / 1_000_000) / 3600
        found.append(f"the metrics collector stopped {hours:.1f} hours ago")
    disk = latest.get(("disk_used_ratio", ""))
    if disk is not None and disk >= DISK_FULL:
        left = (1 - disk) * latest.get(("disk_total_bytes", ""), 0)
        found.append(f"disk {disk:.0%} full ({format_bytes(left)} left)")
    stuck = latest.get(("established_no_timer", ""))
    if stuck is not None and stuck >= STUCK_SOCKETS:
        found.append(f"{int(stuck)} ESTABLISHED sockets with no timer armed, the shape of the timeout bug")
    if latest.get(("reboot_required", "")):
        found.append("reboot required")
    updates = latest.get(("pkg_updates", ""))
    if updates:
        found.append(f"{int(updates)} package update(s) pending")
    fired = latest.get(("timer_last_fired", GEODATA_TIMER))
    if fired and (now - fired) / 86400 > GEODATA_DAYS:
        found.append(f"geodata last refreshed {(now - fired) / 86400:.0f} days ago")
    return found


def panel_problems(panel: dict | None, panel_error: str | None) -> list[str]:
    """Open items the panel shows: nodes it sees offline, clients near a limit"""
    if panel is None:
        return [f"the panel database did not answer: {panel_error}"]
    found = []
    for node in panel.get("nodes", []):
        if not node["online"]:
            found.append(f"node {node['name']} is offline as the panel sees it")
    for client in panel.get("clients", []):
        if not client["enable"]:
            continue
        if client["cap_share"] is not None and client["cap_share"] >= CAP_SHARE:
            found.append(f"client {client['label']} is at {client['cap_share']:.0%} of its traffic limit")
        if client["expires_days"] is not None and 0 <= client["expires_days"] <= EXPIRY_DAYS:
            found.append(f"client {client['label']} expires in {client['expires_days']:.0f} days")
    return found
