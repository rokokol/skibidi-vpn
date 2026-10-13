"""The alert unit's order of work: the station first, the mail as the fallback.

A failed self-check pushes at once, so the station sees the problem within
seconds and can alert by its own relay while the mail node is down. Only if
that push fails does this node mail the journal itself. Any other failed unit
has no problem series to push and mails as it always did. The script is
rendered from the real template and run in bash with stubs for every tool.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from jinja2 import Environment

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "roles" / "checker" / "templates" / "skibidi-alert.j2"


class AlertCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.mail = self.dir / "mail.eml"
        self.pushes = self.dir / "pushes"
        self.recipient = self.dir / "alert-to"
        self.recipient.write_text("ops@example.test\n")
        self.stub("sendmail", f"cat > {self.mail}")
        self.stub("journalctl", "echo 'FAIL nginx is not running'")
        self.stub("systemctl", "echo ''")
        self.stub("hostname", "echo test-node")
        self.push_rc = 0
        self.script = self.dir / "skibidi-alert"

    def stub(self, name, body):
        path = self.bin / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)

    def run_alert(self, unit, push_rc=0, recipient=True):
        push = self.dir / "push-command"
        push.write_text(f"#!/bin/sh\necho called >> {self.pushes}\nexit {push_rc}\n")
        push.chmod(0o755)
        text = Environment(trim_blocks=True).from_string(TEMPLATE.read_text()).render(
            ansible_managed="rendered by the test",
            checker_alert_push=str(push),
            checker_alert_to_file=str(self.recipient),
        )
        self.script.write_text(text)
        if not recipient:
            self.recipient.unlink()
        env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}"}
        done = subprocess.run(["bash", str(self.script), unit], capture_output=True, text=True,
                              env=env, check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done

    def pushed(self):
        return self.pushes.exists()

    def mailed(self):
        return self.mail.exists()


class TestStationFirst(AlertCase):
    def test_a_failed_check_is_pushed_and_not_mailed(self):
        self.run_alert("skibidi-check")
        self.assertTrue(self.pushed())
        self.assertFalse(self.mailed(), "the station has it; a second alarm by mail would be noise")

    def test_the_unit_name_may_carry_its_suffix(self):
        self.run_alert("skibidi-check.service")
        self.assertTrue(self.pushed())
        self.assertFalse(self.mailed())

    def test_a_push_that_fails_falls_back_to_the_mail(self):
        self.run_alert("skibidi-check", push_rc=1)
        self.assertTrue(self.pushed())
        self.assertTrue(self.mailed())
        self.assertIn("nginx is not running", self.mail.read_text())

    def test_a_node_with_no_station_mails_as_it_did(self):
        # The push command answers 3 for "this node names no station"
        self.run_alert("skibidi-check", push_rc=3)
        self.assertTrue(self.mailed())

    def test_the_push_happens_even_when_no_one_is_to_be_mailed(self):
        self.run_alert("skibidi-check", recipient=False)
        self.assertTrue(self.pushed())

    def test_without_a_recipient_a_failed_push_mails_nobody_and_is_not_an_error(self):
        self.run_alert("skibidi-check", push_rc=1, recipient=False)
        self.assertFalse(self.mailed())


class TestOtherUnitsStillMail(AlertCase):
    def test_a_failed_daily_list_is_mailed_not_pushed(self):
        # The daily list is the mail; the station has no series for it
        self.run_alert("skibidi-daily")
        self.assertFalse(self.pushed())
        self.assertTrue(self.mailed())

    def test_a_failed_backup_is_mailed_not_pushed(self):
        self.run_alert("skibidi-backup")
        self.assertFalse(self.pushed())
        self.assertTrue(self.mailed())

    def test_a_unit_that_merely_starts_with_the_checks_name_is_another_unit(self):
        self.run_alert("skibidi-check-extra")
        self.assertFalse(self.pushed())


if __name__ == "__main__":
    unittest.main(verbosity=2)
