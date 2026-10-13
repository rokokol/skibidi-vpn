"""What skibidi-check leaves behind for the daily check to read.

The daily check must not run every check a second time: some of them keep
state between runs, and a second run would count twice. So each run records
the failures it ended with, and the daily check reads that record. The head of
the script (the `fail` function) and the record section are rendered from the
real template and run in bash.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from jinja2 import Environment

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "roles" / "checker" / "templates" / "skibidi-check.j2"


def script(state_dir: str, calls: str) -> str:
    source = TEMPLATE.read_text()
    head = source[source.index("failures=0"):source.index("# --- services")]
    record = source[source.index("# --- the record"):source.index("# The summary goes last")]
    values = {"checker_result_file": f"{state_dir}/failures", "ansible_managed": "rendered by the test"}
    render = Environment(trim_blocks=True).from_string
    return render(head).render(**values) + calls + "\n" + render(record).render(**values)


class TestRecord(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name) / "state"
        self.record = self.state / "failures"

    def run_checks(self, calls: str):
        result = subprocess.run(["bash", "-c", script(str(self.state), calls)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.returncode, 0)
        return result.stdout

    def test_each_failure_is_one_line_of_the_record_with_its_cause_first(self):
        self.run_checks("fail unit.nginx.down 'nginx is not running'\nok 'x is fine'\n"
                        "fail ufw.inactive 'ufw is not active'")
        self.assertEqual(self.record.read_text().splitlines(),
                         ["unit.nginx.down\tnginx is not running", "ufw.inactive\tufw is not active"])

    def test_a_run_that_passed_leaves_an_empty_record_not_none(self):
        # An absent record means the check never ran; an empty one means it
        # ran and found nothing
        self.run_checks("ok 'everything'")
        self.assertTrue(self.record.exists())
        self.assertEqual(self.record.read_text(), "")

    def test_a_newer_run_replaces_the_older_record(self):
        self.run_checks("fail some.cause 'old trouble'")
        self.run_checks("ok 'fixed'")
        self.assertEqual(self.record.read_text(), "")

    def test_a_message_that_spans_lines_stays_one_line(self):
        self.run_checks("fail firewall.unexpected-open \"the firewall also allows\n80/tcp\"")
        self.assertEqual(len(self.record.read_text().splitlines()), 1)

    def test_the_record_is_replaced_whole_and_leaves_no_scratch_file(self):
        self.run_checks("fail some.cause 'a'")
        self.assertEqual(sorted(path.name for path in self.state.iterdir()), ["failures"])

    def test_the_key_is_for_the_record_and_not_for_the_reader(self):
        out = self.run_checks("fail unit.nginx.down 'nginx is not running'")
        self.assertNotIn("unit.nginx.down", out)

    def test_every_call_in_the_check_names_its_cause(self):
        # A call without a key would record the message as the key and the
        # next word of it as the message, and the station would see nonsense
        source = TEMPLATE.read_text()
        calls = [line.strip() for line in source.splitlines() if line.strip().startswith(("fail ", "*) fail "))
                 or " fail \"" in line or " fail $" in line]
        self.assertTrue(calls)
        for call in calls:
            body = call.split("fail ", 1)[1]
            self.assertRegex(body, r'^("[^"]+"|[A-Za-z0-9._-]+) ["$]', call)

    def test_the_output_still_carries_the_fail_lines_the_alert_mail_reads(self):
        out = self.run_checks("fail unit.nginx.down 'nginx is not running'")
        self.assertIn("FAIL nginx is not running", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
