"""Showcase samples on clean, realistic, synthetic data — the adversarial
fixtures belong to the tests, not to a demo anyone reads.

    nix develop .#ci -c python3 tests/make-samples.py    # writes ./samples/*.html

The theme files come from the dev shell's environment; outside it the letters
render in the neutral fallback, which is itself worth seeing once."""

import base64
import datetime as dt
import importlib.util
import os
import sys
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "samples"
OUT.mkdir(parents=True, exist_ok=True)

os.environ["MPLCONFIGDIR"] = str(OUT / ".mpl")
os.environ["SKIBIDI_REPORT_CSS_FILE"] = os.environ.get("SKIBIDI_REPORT_CSS", "")
os.environ["SKIBIDI_MPLSTYLE_FILE"] = os.environ.get("SKIBIDI_MPLSTYLE", "")
os.environ["SKIBIDI_CHART_FONT_FILE"] = os.environ.get("SKIBIDI_CHART_FONT", "")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


report = load("skibidi_report", ROOT / "roles/reporter/files/skibidi-report.py")
alert = load("skibidi_alert", ROOT / "roles/checker/files/skibidi-alert-html.py")

ZONE = ZoneInfo("Europe/Moscow")
START = dt.datetime(2026, 8, 24, 9, tzinfo=ZONE)
END = dt.datetime(2026, 8, 31, 9, tzinfo=ZONE)
GIB = 2**30

ALERT_BODY = """skibidi-check.service failed on node-b at 2026-08-31T09:07:12+00:00.

ok   x-ui is running
ok   nginx is running
ok   fail2ban is running
ok   tailscaled is running
ok   congestion control is declared in exactly one file
ok   net.ipv4.tcp_congestion_control is bbr
ok   conntrack 1% used (784 of 65536)
ok   ufw is active
FAIL the firewall also allows 9999/tcp, which this node does not declare
ok   note: udp/8443 listens publicly but the firewall does not admit it
ok   the tailscale direct path is dropped
ok   fail2ban jail sshd answers
ok   the panel answers only on its tunnel address
ok   inbound port 443 is served
ok   inbound port 8443 is served
ok   skibidi-check.timer fired 0h ago
ok   xray-geodata-update.timer fired 14h ago
ok   skibidi-metrics.timer fired 0h ago
ok   the master answers
ok   xray accepts its generated configuration
1 check(s) failed on node-b
"""


def report_data():
    days = [START.date() + dt.timedelta(days=n) for n in range(7)]
    inbound_series = []
    volumes = [11, 14, 9, 16, 21, 26, 18]
    for day, total in zip(days, volumes):
        inbound_series.append((day, {
            "SE-exit": int(total * 0.62 * GIB),
            "RU-transit": int(total * 0.28 * GIB),
            "backup-door": int(total * 0.10 * GIB),
        }))
    exports = {
        "node-a": {"collected_through_us": int(END.timestamp() * 1e6),
                   "samples": [[int((START + dt.timedelta(hours=h)).timestamp() * 1e6),
                                "load1", "", 0.3 + 0.25 * ((h % 24) > 18) + (h % 7) * 0.03]
                               for h in range(0, 168, 2)]},
        "node-b": {"collected_through_us": int(END.timestamp() * 1e6),
                   "samples": [[int((START + dt.timedelta(hours=h)).timestamp() * 1e6),
                                "load1", "", 0.15 + (h % 5) * 0.02]
                               for h in range(0, 168, 2)]},
    }
    data = {
        "start": START, "end": END, "timezone": "Europe/Moscow", "days": days,
        "exports": exports,
        "unreachable": [], "stale": [], "window_incomplete": False,
        "inbound_series": inbound_series,
        "client_deltas": [("Артемий", 34 * GIB), ("Бабушка", 21 * GIB),
                          ("Мама", 12 * GIB), ("Папа", 9 * GIB), ("Илья", 4 * GIB)],
        "bans_by_day": {days[0]: 3, days[2]: 7, days[3]: 2, days[5]: 11, days[6]: 4},
        "drops_by_day": {day: count for day, count in zip(days, [140, 95, 210, 180, 160, 330, 120])},
        "ssh_attempts": {"node-a": 1243, "node-b": 890},
        "unit_restart_deltas": [("node-b/x-ui", 2)],
        "geodata_age": {"node-a": 0.6, "node-b": 0.6},
        "health": None,
        "panel": {
            "nodes": [{"name": "node-b", "online": True, "heartbeat": 0,
                       "latency_ms": 41, "cpu": 3, "mem": 22,
                       "panel_version": "3.7.0", "xray_version": "25.1.31"}],
            "clients": [
                {"label": "Дядя", "inbound": "SE-exit", "enable": True,
                 "silent_days": 44.0, "cap_share": None, "expires_days": None},
                {"label": "Бабушка", "inbound": "SE-exit", "enable": True,
                 "silent_days": 0.2, "cap_share": 0.93, "expires_days": None},
            ],
            "versions": {"master": {"panel": "3.7.0", "xray": "25.1.31"}},
        },
        "changes": [
            "inbound added: backup-door",
            "clients added to SE-exit: Илья",
            "routing rules: 1 added, 0 removed",
        ],
    }
    data["health"] = [
        {"node": "node-a", "uptime": 41 * 86400, "load_max": 1.42, "mem_last": 0.44,
         "disk_last": 0.31, "disk_total": 80 * GIB, "conntrack_max": 0.021,
         "stuck_last": 3, "stuck_max": 9, "updates": 4, "reboot": False},
        {"node": "node-b", "uptime": 12 * 86400, "load_max": 0.61, "mem_last": 0.29,
         "disk_last": 0.47, "disk_total": 40 * GIB, "conntrack_max": 0.012,
         "stuck_last": 1, "stuck_max": 2, "updates": 11, "reboot": True},
    ]
    data["alerts"] = report.collect_alerts(data)
    return data


def inline(message):
    body, images = None, {}
    for part in message.walk():
        if part.get_content_type() == "text/html":
            body = part.get_content()
        elif part.get_content_type() == "image/png":
            images[part["Content-ID"].strip("<>")] = base64.b64encode(
                part.get_payload(decode=True)).decode()
    for cid, data in images.items():
        body = body.replace(f"cid:{cid}", f"data:image/png;base64,{data}")
    return body


letter = report.build_message(report_data(), "skibidi-vpn@node-a", "vpn@example.org")
(OUT / "report-sample.html").write_text(inline(letter))

message = alert.build_message(
    ALERT_BODY, "skibidi-check.service", "node-b",
    "[node-b] 1 check(s) failed on node-b",
    "vpn@example.org", "skibidi-vpn@node-b", os.environ["SKIBIDI_REPORT_CSS_FILE"],
)
(OUT / "alert-sample.html").write_text(inline(message))
print("clean samples written")
