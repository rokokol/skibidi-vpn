"""Showcase samples on clean, realistic, synthetic data — the adversarial
fixtures belong to the tests, not to a demo anyone reads.

    nix develop .#ci -c python3 tests/make-samples.py    # writes ./samples/*.html

The theme file comes from the dev shell's environment; outside it the letters
render in the neutral fallback, which is itself worth seeing once."""

import importlib.util
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "samples"
OUT.mkdir(parents=True, exist_ok=True)

os.environ["SKIBIDI_MAIL_FILE"] = os.environ.get("SKIBIDI_MAIL", "")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


alert = load("skibidi_alert", ROOT / "roles/checker/files/skibidi-alert-html.py")

# The urgent level: a check that failed, mailed within half an hour
ALERT_BODY = """skibidi-check.service failed on node-b at 2026-08-31T09:07:12+00:00.

ok   x-ui is running
ok   nginx is running
ok   fail2ban is running
ok   tailscaled is running
ok   ufw is active
FAIL the firewall also allows 9999/tcp, which this node does not declare
ok   the tailscale direct path is dropped
ok   fail2ban jail sshd answers
ok   the panel answers only on its tunnel address
ok   xray accepts its generated configuration
1 check(s) failed on node-b
"""

# The daily level: everything still open, urgent or not
DAILY_BODY = """skibidi-daily.service failed on node-b at 2026-08-31T06:00:41+00:00.

FAIL the firewall also allows 9999/tcp, which this node does not declare
FAIL reboot required
FAIL 11 package update(s) pending
FAIL geodata last refreshed 9 days ago
FAIL client Бабушка is at 93% of its traffic limit
5 unresolved item(s) on node-b
"""

for name, unit, body in (
    ("alert", "skibidi-check.service", ALERT_BODY),
    ("daily", "skibidi-daily.service", DAILY_BODY),
):
    message = alert.build_message(
        body, unit, "node-b", f"[node-b] {body.strip().splitlines()[-1]}",
        "vpn@example.org", "skibidi-vpn@node-b", os.environ["SKIBIDI_MAIL_FILE"],
    )
    (OUT / f"{name}-sample.html").write_text(
        next(part for part in message.walk() if part.get_content_type() == "text/html").get_content())
print("clean samples written")
