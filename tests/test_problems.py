"""What counts as a problem that is still open, defined once.

The urgent half is `skibidi-check`, which fails a node within half an hour.
This module is the other half: the open items that wait for the daily mail,
read from the numbers a node samples and from the panel on the master. Every
rule is run once quiet and once tripped, because a rule that has only ever
been quiet proves nothing.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "roles" / "metrics" / "files"))

import skibidi_problems as problems  # noqa: E402

NOW = 1_790_000_000.0
DAY = 86400


def quiet_latest(overrides=None):
    values = {
        ("disk_used_ratio", ""): 0.40,
        ("disk_total_bytes", ""): 50e9,
        ("established_no_timer", ""): 3.0,
        ("reboot_required", ""): 0.0,
        ("pkg_updates", ""): 0.0,
        ("timer_last_fired", "xray-geodata-update.timer"): NOW - DAY,
    }
    values.update(overrides or {})
    return values


def healthy(lag_seconds=60):
    return {"status": "ok", "collected_through_us": int((NOW - lag_seconds) * 1_000_000)}


class TestNodeProblems(unittest.TestCase):
    def test_a_quiet_node_has_nothing_open(self):
        self.assertEqual(problems.node_problems(quiet_latest(), healthy(), NOW), [])

    def one(self, latest=None, health=None):
        found = problems.node_problems(latest or quiet_latest(), health or healthy(), NOW)
        self.assertEqual(len(found), 1, found)
        return found[0]

    def test_a_nearly_full_disk_is_open_and_says_how_much_is_left(self):
        text = self.one(quiet_latest({("disk_used_ratio", ""): 0.90}))
        self.assertIn("disk", text)
        self.assertIn("90%", text)
        self.assertIn("GiB", text)

    def test_the_disk_limit_is_inclusive(self):
        self.assertEqual(len(problems.node_problems(
            quiet_latest({("disk_used_ratio", ""): problems.DISK_FULL}), healthy(), NOW)), 1)

    def test_sockets_stuck_without_a_timer_are_open(self):
        text = self.one(quiet_latest({("established_no_timer", ""): 250.0}))
        self.assertIn("250", text)
        self.assertIn("timer", text)

    def test_a_reboot_that_is_required_is_open(self):
        self.assertIn("reboot", self.one(quiet_latest({("reboot_required", ""): 1.0})))

    def test_pending_updates_are_open_with_their_number(self):
        text = self.one(quiet_latest({("pkg_updates", ""): 7.0}))
        self.assertIn("7", text)
        self.assertIn("update", text)

    def test_stale_geodata_is_open_with_its_age(self):
        old = quiet_latest({("timer_last_fired", "xray-geodata-update.timer"): NOW - 12 * DAY})
        text = self.one(old)
        self.assertIn("geodata", text)
        self.assertIn("12", text)

    def test_geodata_that_never_refreshed_is_not_invented(self):
        # No sample is no verdict: the collector's own freshness is the rule
        # that notices a node that stopped sampling
        latest = quiet_latest()
        del latest[("timer_last_fired", "xray-geodata-update.timer")]
        self.assertEqual(problems.node_problems(latest, healthy(), NOW), [])

    def test_a_collector_that_stopped_is_open(self):
        text = self.one(health=healthy(lag_seconds=3 * 3600))
        self.assertIn("collector", text)

    def test_a_collector_that_never_ran_is_open(self):
        text = self.one(health={"status": "starting", "collected_through_us": None})
        self.assertIn("collector", text)

    def test_every_open_item_is_listed_not_only_the_worst(self):
        found = problems.node_problems(quiet_latest({
            ("reboot_required", ""): 1.0,
            ("pkg_updates", ""): 3.0,
            ("disk_used_ratio", ""): 0.95,
        }), healthy(), NOW)
        self.assertEqual(len(found), 3)

    def test_conntrack_is_the_checks_to_report_not_this_modules(self):
        # skibidi-check fails above 80% within half an hour; a second rule
        # here would put the same fact into the daily mail twice
        found = problems.node_problems(
            quiet_latest({("conntrack_used_ratio", ""): 0.99}), healthy(), NOW)
        self.assertEqual(found, [])


def panel(**overrides):
    values = {
        "nodes": [{"name": "node-b", "online": True}],
        "clients": [{"label": "Grandmother", "enable": True, "cap_share": 0.2, "expires_days": 90.0}],
    }
    values.update(overrides)
    return values


class TestPanelProblems(unittest.TestCase):
    def test_a_quiet_panel_has_nothing_open(self):
        self.assertEqual(problems.panel_problems(panel(), None), [])

    def test_a_node_the_panel_sees_offline_is_open(self):
        found = problems.panel_problems(panel(nodes=[{"name": "node-b", "online": False}]), None)
        self.assertEqual(len(found), 1)
        self.assertIn("node-b", found[0])

    def test_a_client_near_its_cap_is_open(self):
        found = problems.panel_problems(panel(clients=[
            {"label": "Grandmother", "enable": True, "cap_share": 0.93, "expires_days": None}]), None)
        self.assertEqual(len(found), 1)
        self.assertIn("Grandmother", found[0])
        self.assertIn("93%", found[0])

    def test_a_client_near_its_expiry_is_open_a_client_long_expired_is_not(self):
        near = {"label": "Mo", "enable": True, "cap_share": None, "expires_days": 3.0}
        gone = {"label": "Old", "enable": True, "cap_share": None, "expires_days": -40.0}
        found = problems.panel_problems(panel(clients=[near, gone]), None)
        self.assertEqual(len(found), 1)
        self.assertIn("Mo", found[0])

    def test_a_disabled_client_is_nobody_s_problem(self):
        off = {"label": "Off", "enable": False, "cap_share": 0.99, "expires_days": 1.0}
        self.assertEqual(problems.panel_problems(panel(clients=[off]), None), [])

    def test_a_panel_that_did_not_answer_is_open(self):
        found = problems.panel_problems(None, "no panel database at /etc/x-ui/x-ui.db")
        self.assertEqual(len(found), 1)
        self.assertIn("panel", found[0])


class TestCheckRecords(unittest.TestCase):
    """The one reading of the self-check's record, for the daily list and the push"""

    def setUp(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.record = Path(tmp.name) / "failures"

    def stale(self):
        import os
        import time
        old = time.time() - 5 * 3600
        os.utime(self.record, (old, old))

    def test_a_fresh_record_gives_each_line_as_a_cause_and_a_message(self):
        self.record.write_text("unit.nginx.down\tnginx is not running\n\nufw.inactive\tufw is not active\n")
        self.assertEqual(problems.check_records(self.record, 2),
                         [("unit.nginx.down", "nginx is not running"),
                          ("ufw.inactive", "ufw is not active")])

    def test_the_daily_list_reads_the_messages_of_the_same_records(self):
        self.record.write_text("unit.nginx.down\tnginx is not running\n")
        self.assertEqual(problems.check_failures(self.record, 2), ["nginx is not running"])

    def test_a_line_without_a_cause_gets_one_made_of_its_words(self):
        # A record an older check wrote; the next run replaces it within the hour
        self.record.write_text("nginx is not running\n")
        [(key, message)] = problems.check_records(self.record, 2)
        self.assertEqual(message, "nginx is not running")
        self.assertRegex(key, r"^[A-Za-z0-9._-]+$")

    def test_an_empty_fresh_record_is_no_failure(self):
        self.record.write_text("")
        self.assertEqual(problems.check_records(self.record, 2), [])

    def test_a_missing_record_is_one_problem_with_a_cause_of_its_own(self):
        [(key, _message)] = problems.check_records(self.record, 2)
        self.assertEqual(key, "check.record-missing")

    def test_a_stale_record_is_one_problem_with_another_cause_and_hides_its_lines(self):
        self.record.write_text("a.b\tfirst\nc.d\tsecond\n")
        self.stale()
        [(key, message)] = problems.check_records(self.record, 2)
        self.assertEqual(key, "check.record-stale")
        self.assertNotIn("first", message)

    def test_the_two_causes_differ_because_the_remedies_differ(self):
        missing = problems.check_records(self.record, 2)[0][0]
        self.record.write_text("")
        self.stale()
        self.assertNotEqual(missing, problems.check_records(self.record, 2)[0][0])


class TestSummary(unittest.TestCase):
    def test_a_summary_is_the_first_clause_of_the_message(self):
        self.assertEqual(
            problems.summary("the 3x-ipl jail does not read /var/log/x.log; it watches the journal"),
            "the 3x-ipl jail does not read /var/log/x.log")

    def test_a_long_message_is_cut_to_a_line(self):
        found = problems.summary("x" * 500)
        self.assertLessEqual(len(found), problems.SUMMARY_LIMIT)
        self.assertNotIn("\n", problems.summary("a\nb"))

    def test_a_cause_is_made_safe_for_a_label_the_station_matches_on(self):
        self.assertEqual(problems.cause_key("timer.skibidi check.timer/x"), "timer.skibidi-check.timer-x")
        self.assertEqual(problems.cause_key(""), "unknown")


class TestFormatBytes(unittest.TestCase):
    def test_units_step_by_1024(self):
        self.assertEqual(problems.format_bytes(512), "512 B")
        self.assertEqual(problems.format_bytes(2048), "2.0 KiB")
        self.assertEqual(problems.format_bytes(3 * 2**30), "3.0 GiB")


if __name__ == "__main__":
    unittest.main(verbosity=2)
