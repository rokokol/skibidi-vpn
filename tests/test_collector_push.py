"""The collector's push: what a node tells the station after each sample.

The probes read /proc and run system tools, so they are replaced by fakes; the
store, the push and the station are real. The station is a Pushgateway stub
that refuses what the real one refuses.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "roles" / "metrics" / "files"
SCRIPT = LIB / "skibidi-metrics.py"
os.environ["SKIBIDI_LIB"] = str(LIB)
sys.path.insert(0, str(LIB))

from pushgateway_stub import Stub, parse_exposition  # noqa: E402

PASSWORD = "p:ss%w@rd"
SECOND = 1_000_000


def load():
    spec = importlib.util.spec_from_file_location("skibidi_metrics", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["skibidi_metrics"] = module
    spec.loader.exec_module(module)
    return module


class PushCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.db = self.dir / "metrics.db"
        self.login_file = self.dir / "rest-password"
        self.login_file.write_text(PASSWORD)
        self.stub = Stub("node-a", PASSWORD).start()
        self.addCleanup(self.stub.stop)
        saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(saved)))
        os.environ["SKIBIDI_METRICS_DB"] = str(self.db)
        self.configure()
        self.module = load()
        self.rows = []
        self.drops = []
        # The probes that read the machine are replaced; collect() still runs
        # every one of them through its own failure handling
        self.module.PROBES = [lambda: iter(self.rows)]
        self.module.probe_updates = lambda connection, now_us: iter(())
        self.module.probe_ufw_drops = lambda connection, now_us: iter(self.drops)

    def configure(self):
        os.environ.update({
            "SKIBIDI_PUSH_BASE": f"http://127.0.0.1:{self.stub.port}",
            "SKIBIDI_PUSH_USER": "node-a",
            "SKIBIDI_PUSH_PASSWORD_FILE": str(self.login_file),
        })

    def unconfigure(self):
        for key in ("SKIBIDI_PUSH_BASE", "SKIBIDI_PUSH_USER", "SKIBIDI_PUSH_PASSWORD_FILE"):
            os.environ.pop(key, None)

    def collect(self, *flags):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            code = self.module.main(["collect", *flags])
        return code, errors.getvalue()

    def pushed(self, index=-1):
        request = self.stub.requests[index]
        self.assertEqual(request["status"], 200, request["reason"])
        return parse_exposition(request["body"])


class TestWhatIsPushed(PushCase):
    def test_the_samples_of_the_run_arrive_under_the_dashboard_s_names(self):
        self.rows = [
            ("load1", "", 0.5),
            ("disk_used_ratio", "", 0.4),
            ("f2b_banned_total", "sshd", 412.0),
            ("f2b_banned_now", "sshd", 2.0),
            ("unit_restarts", "x-ui", 3.0),
            ("timer_last_fired", "skibidi-check.timer", 1.7e9),
            ("pkg_updates", "", 4.0),
            ("reboot_required", "", 1.0),
        ]
        self.assertEqual(self.collect()[0], 0)
        families = self.pushed()
        self.assertEqual(families["vpn_load1"]["samples"], [({}, 0.5)])
        self.assertEqual(families["vpn_disk_used_ratio"]["type"], "gauge")
        self.assertEqual(families["vpn_fail2ban_banned_total"]["type"], "counter")
        self.assertEqual(families["vpn_fail2ban_banned_total"]["samples"], [({"jail": "sshd"}, 412.0)])
        self.assertEqual(families["vpn_fail2ban_banned"]["samples"], [({"jail": "sshd"}, 2.0)])
        self.assertEqual(families["vpn_unit_restarts_total"]["samples"], [({"unit": "x-ui"}, 3.0)])
        self.assertEqual(families["vpn_timer_last_fired_timestamp_seconds"]["samples"],
                         [({"timer": "skibidi-check.timer"}, 1.7e9)])
        self.assertEqual(families["vpn_pending_updates"]["samples"], [({}, 4.0)])
        self.assertEqual(families["vpn_reboot_required"]["samples"], [({}, 1.0)])

    def test_every_pushed_name_is_prefixed_and_no_name_holds_the_node(self):
        self.rows = [("load1", "", 0.5), ("mem_used_ratio", "", 0.2), ("uptime_seconds", "", 9.0)]
        self.collect()
        for name in self.pushed():
            self.assertTrue(name.startswith("vpn_"), name)
            self.assertNotIn("node", name)

    def test_the_push_goes_to_the_nodes_own_group(self):
        self.rows = [("load1", "", 0.5)]
        self.collect()
        self.assertEqual(self.stub.requests[0]["path"], "/metrics/job/vpn/instance/node-a")

    def test_a_series_older_than_the_window_is_not_pushed(self):
        # A probe that stopped answering leaves its last value in the store;
        # pushing it again would make a dead probe look alive
        import time
        self.rows = [("load1", "", 0.5)]
        self.collect()
        with self.module.connect() as connection:
            # Three hours old: outside the window, and inside the retention
            # that the collection would otherwise prune it by
            connection.execute("INSERT INTO samples VALUES (?, 'reboot_required', '', 1.0)",
                               (int((time.time() - 3 * 3600) * SECOND),))
        self.rows = [("load1", "", 0.7)]
        self.collect()
        families = self.pushed()
        self.assertIn("vpn_load1", families)
        self.assertNotIn("vpn_reboot_required", families)

    def test_the_newest_value_of_a_slow_probe_is_pushed_beside_the_fresh_ones(self):
        # The updates probe runs hourly; the run in between still reports it
        import time
        hour_ago = int((time.time() - 3000) * SECOND)
        self.rows = [("load1", "", 0.5)]
        with self.module.connect() as connection:
            connection.execute("INSERT INTO samples VALUES (?, 'pkg_updates', '', 9.0)", (hour_ago,))
        self.collect()
        self.assertEqual(self.pushed()["vpn_pending_updates"]["samples"], [({}, 9.0)])

    def test_ufw_drops_are_pushed_as_a_running_total(self):
        self.drops = [("ufw_drops", "", 5.0)]
        self.collect()
        self.drops = [("ufw_drops", "", 7.0)]
        self.collect()
        family = self.pushed()["vpn_ufw_drops_total"]
        self.assertEqual(family["type"], "counter")
        self.assertEqual(family["samples"], [({}, 12.0)])

    def test_a_node_that_never_counted_drops_pushes_no_total(self):
        self.rows = [("load1", "", 0.5)]
        self.collect()
        self.assertNotIn("vpn_ufw_drops_total", self.pushed())

    def test_every_metric_a_probe_writes_has_a_name_for_the_dashboard(self):
        source = SCRIPT.read_text()
        written = set(re.findall(r'yield "([a-z0-9_]+)"', source))
        written |= set(self.module.COUNTERS) | set(self.module.DIMENSIONS)
        written |= set(re.findall(r'\("[A-Za-z ]+", "([a-z0-9_]+)"\)', source))
        missing = written - set(self.module.PROMETHEUS) - {"ufw_drops"}
        self.assertEqual(missing, set(), "a sampled metric never reaches the dashboard")


class TestNodeProblems(PushCase):
    """One series per open urgent problem, from the self-check's record. The
    station alerts on each while it stays in the group, and the push replaces
    the group, so a solved problem leaves with the next push"""

    def setUp(self):
        super().setUp()
        self.record = self.dir / "failures"
        self.record.write_text("")
        os.environ["SKIBIDI_CHECK_RESULT"] = str(self.record)
        os.environ["SKIBIDI_CHECK_MAX_AGE_HOURS"] = "2"
        self.rows = [("load1", "", 0.5)]

    def problems(self):
        self.collect()
        family = self.pushed().get("node_problem")
        return {} if family is None else {
            labels["key"]: (labels["summary"], value) for labels, value in family["samples"]}

    def test_each_open_problem_is_a_series_of_value_one_with_its_cause_and_summary(self):
        self.record.write_text("unit.nginx.down\tnginx is not running\nufw.inactive\tufw is not active\n")
        self.assertEqual(self.problems(), {"unit.nginx.down": ("nginx is not running", 1.0),
                                           "ufw.inactive": ("ufw is not active", 1.0)})

    def test_the_family_is_a_gauge_with_the_agreed_help(self):
        self.record.write_text("a.b\tsomething\n")
        self.collect()
        family = self.pushed()["node_problem"]
        self.assertEqual(family["type"], "gauge")
        self.assertEqual(family["help"], "One unresolved problem this node reports of itself, by cause")

    def test_a_clean_check_pushes_no_series_and_a_solved_problem_is_missing_from_the_next_body(self):
        self.record.write_text("unit.nginx.down\tnginx is not running\n")
        self.assertEqual(list(self.problems()), ["unit.nginx.down"])
        self.record.write_text("")
        self.assertEqual(self.problems(), {})
        self.assertEqual(self.stub.requests[-1]["method"], "PUT",
                         "only a replacing push takes the old series off the station")

    def test_a_missing_record_is_one_problem_with_its_own_cause(self):
        self.record.unlink()
        self.assertEqual(list(self.problems()), ["check.record-missing"])

    def test_a_stale_record_is_one_problem_whatever_it_holds(self):
        self.record.write_text("a.b\tone\nc.d\ttwo\nd.e\tthree\n")
        old = time.time() - 5 * 3600
        os.utime(self.record, (old, old))
        self.assertEqual(list(self.problems()), ["check.record-stale"])

    def test_the_quiet_items_of_the_daily_check_are_not_problems(self):
        self.rows = [("load1", "", 0.5), ("reboot_required", "", 1.0), ("pkg_updates", "", 30.0),
                     ("disk_used_ratio", "", 0.95)]
        self.assertEqual(self.problems(), {})

    def test_the_summary_is_one_short_clause(self):
        self.record.write_text("a.b\tthe jail does not read the log; it watches the journal and bans nobody\n")
        [(summary, _value)] = self.problems().values()
        self.assertEqual(summary, "the jail does not read the log")

    def test_a_cause_that_repeats_is_one_series(self):
        # Two series with one key would be one alert twice
        self.record.write_text("a.b\tfirst\na.b\tsecond\n")
        self.assertEqual(self.problems(), {"a.b": ("first", 1.0)})

    def test_a_cause_with_characters_a_label_matcher_dislikes_is_made_safe(self):
        self.record.write_text("timer.skibidi check.timer/x\tsilent\n")
        self.assertEqual(list(self.problems()), ["timer.skibidi-check.timer-x"])

    def test_the_name_has_no_prefix_and_the_rest_keep_theirs(self):
        self.record.write_text("a.b\tsomething\n")
        self.collect()
        names = list(self.pushed())
        self.assertEqual([name for name in names if not name.startswith("vpn_")], ["node_problem"])

    def test_without_the_check_settings_nothing_is_said_of_problems(self):
        # Not "none": a node that cannot read its record must not claim to be clean
        del os.environ["SKIBIDI_CHECK_RESULT"]
        self.record.write_text("a.b\tsomething\n")
        self.collect()
        self.assertNotIn("node_problem", self.pushed())

    def test_the_old_gauge_is_gone(self):
        self.collect()
        self.assertNotIn("node_problems", self.pushed())


class TestTextfile(PushCase):
    """The master's traffic arrives as a file, so the group has one writer"""

    GOOD = ("# HELP vpn_client_traffic_bytes_total x\n# TYPE vpn_client_traffic_bytes_total counter\n"
            "vpn_client_traffic_bytes_total{client=\"Mo\",direction=\"up\"} 5.0\n")

    def setUp(self):
        super().setUp()
        self.textfile = self.dir / "traffic.prom"
        os.environ["SKIBIDI_PUSH_TEXTFILE"] = str(self.textfile)
        self.rows = [("load1", "", 0.5)]

    def test_a_fresh_file_rides_in_the_same_body(self):
        self.textfile.write_text(self.GOOD)
        self.collect()
        families = self.pushed()
        self.assertIn("vpn_client_traffic_bytes_total", families)
        self.assertIn("vpn_load1", families)
        self.assertEqual(len(self.stub.requests), 1, "a second push to the group would replace the first")

    def test_a_file_nobody_has_refreshed_is_left_out_rather_than_kept_alive(self):
        self.textfile.write_text(self.GOOD)
        old = time.time() - 5 * 3600
        os.utime(self.textfile, (old, old))
        self.collect()
        self.assertNotIn("vpn_client_traffic_bytes_total", self.pushed())

    def test_a_broken_file_costs_its_numbers_and_not_the_push(self):
        self.textfile.write_text("this is not exposition text\n")
        code, errors = self.collect()
        self.assertEqual(code, 0)
        self.assertIn("traffic", errors)
        self.assertIn("vpn_load1", self.pushed())

    def test_a_file_that_names_a_family_the_collector_owns_is_left_out(self):
        self.textfile.write_text("# TYPE vpn_load1 gauge\nvpn_load1 99.0\n")
        self.collect()
        self.assertEqual(self.pushed()["vpn_load1"]["samples"], [({}, 0.5)])

    def test_no_file_is_no_traffic_and_no_complaint(self):
        self.assertEqual(self.collect(), (0, ""))


class TestAttackers(PushCase):
    """Who knocks, read from fail2ban's own log at the moment of the push"""

    def setUp(self):
        super().setUp()
        self.log = self.dir / "fail2ban.log"
        os.environ["SKIBIDI_FAIL2BAN_LOG"] = str(self.log)
        os.environ["SKIBIDI_ATTACK_JAILS"] = "sshd"
        self.rows = [("load1", "", 0.5)]
        self.now = time.time()

    def line(self, age, jail, event, address):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.now - age))
        source = "filter " if event == "Found" else "actions"
        level = "INFO   " if event == "Found" else "NOTICE "
        tail = f" - {stamp}" if event == "Found" else ""
        return f"{stamp},123 fail2ban.{source}        [430]: {level} [{jail}] {event} {address}{tail}\n"

    def write(self, path, lines):
        path.write_text("".join(lines))

    def attempts(self):
        families = self.pushed()
        return {labels["ip"]: value
                for labels, value in families.get("vpn_fail2ban_top_attempts", {"samples": []})["samples"]}

    def bans(self):
        families = self.pushed()
        return families.get("vpn_fail2ban_recent_ban_timestamp_seconds", {"samples": []})["samples"]

    def test_the_attempts_of_the_last_day_are_counted_per_address(self):
        self.write(self.log, [self.line(600, "sshd", "Found", "192.0.2.1")] * 3
                   + [self.line(60, "sshd", "Found", "192.0.2.2")])
        self.collect()
        self.assertEqual(self.attempts(), {"192.0.2.1": 3.0, "192.0.2.2": 1.0})
        self.assertEqual(self.pushed()["vpn_fail2ban_top_attempts"]["type"], "gauge")

    def test_an_attempt_older_than_a_day_is_not_counted(self):
        self.write(self.log, [self.line(25 * 3600, "sshd", "Found", "192.0.2.1"),
                              self.line(60, "sshd", "Found", "192.0.2.2")])
        self.collect()
        self.assertEqual(self.attempts(), {"192.0.2.2": 1.0})

    def test_a_jail_that_is_not_an_attack_is_left_out(self):
        # 3x-ipl bans the operator's own clients, and recidive's findings are
        # bans of other jails, not attempts
        self.write(self.log, [self.line(60, "3x-ipl", "Found", "198.51.100.7"),
                              self.line(60, "recidive", "Found", "192.0.2.1"),
                              self.line(60, "3x-ipl", "Ban", "198.51.100.7"),
                              self.line(60, "sshd", "Found", "192.0.2.1")])
        self.collect()
        self.assertEqual(self.attempts(), {"192.0.2.1": 1.0})
        self.assertEqual(self.bans(), [])

    def test_only_the_busiest_ten_are_pushed(self):
        lines = []
        for index in range(12):
            lines += [self.line(60, "sshd", "Found", f"192.0.2.{index}")] * (index + 1)
        self.write(self.log, lines)
        self.collect()
        self.assertEqual(sorted(self.attempts()), sorted(f"192.0.2.{index}" for index in range(2, 12)))

    def test_the_rotated_log_still_counts_inside_the_day(self):
        self.write(Path(f"{self.log}.1"), [self.line(3600, "sshd", "Found", "192.0.2.1")])
        self.write(self.log, [self.line(60, "sshd", "Found", "192.0.2.1")])
        self.collect()
        self.assertEqual(self.attempts(), {"192.0.2.1": 2.0})

    def test_a_day_that_spans_many_blocks_of_the_log_is_counted_whole(self):
        # The log is read back from its end in blocks, and no line on the
        # border of two blocks may be lost or counted twice
        old = [self.line(3 * 86400, "sshd", "Found", "192.0.2.9")] * 20000
        recent = [self.line(600, "sshd", "Found", "192.0.2.1")] * 3001
        self.write(self.log, old + recent)
        self.collect()
        self.assertEqual(self.attempts(), {"192.0.2.1": 3001.0})

    def test_the_latest_bans_carry_their_time_and_jail(self):
        self.write(self.log, [self.line(7200, "sshd", "Ban", "192.0.2.1"),
                              self.line(600, "sshd", "Restore Ban", "192.0.2.3"),
                              self.line(60, "sshd", "Ban", "192.0.2.2")])
        self.collect()
        bans = {labels["ip"]: (labels["jail"], value) for labels, value in self.bans()}
        self.assertEqual(set(bans), {"192.0.2.1", "192.0.2.2"}, "a restored ban is not a new one")
        self.assertEqual(bans["192.0.2.2"][0], "sshd")
        self.assertAlmostEqual(bans["192.0.2.2"][1], self.now - 60, delta=2)

    def test_an_address_banned_twice_is_one_series_at_its_latest_ban(self):
        self.write(self.log, [self.line(7200, "sshd", "Ban", "192.0.2.1"),
                              self.line(60, "sshd", "Ban", "192.0.2.1")])
        self.collect()
        bans = self.bans()
        self.assertEqual(len(bans), 1)
        self.assertAlmostEqual(bans[0][1], self.now - 60, delta=2)

    def test_only_the_last_ten_bans_are_pushed(self):
        self.write(self.log, [self.line(1000 - index, "sshd", "Ban", f"192.0.2.{index}") for index in range(12)])
        self.collect()
        self.assertEqual(sorted(labels["ip"] for labels, _ in self.bans()),
                         sorted(f"192.0.2.{index}" for index in range(2, 12)))

    def test_the_push_command_carries_them_too(self):
        self.write(self.log, [self.line(60, "sshd", "Found", "192.0.2.1")])
        self.collect("--no-push")
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(self.module.main(["push"]), 0)
        self.assertEqual(self.attempts(), {"192.0.2.1": 1.0})

    def test_no_log_is_no_attackers_and_no_complaint(self):
        self.assertEqual(self.collect(), (0, ""))
        self.assertNotIn("vpn_fail2ban_top_attempts", self.pushed())

    def test_a_line_of_another_shape_is_skipped(self):
        self.write(self.log, ["garbage\n", "2026-13-99 nonsense [sshd] Found x\n",
                              self.line(60, "sshd", "Found", "192.0.2.1")])
        self.assertEqual(self.collect()[0], 0)
        self.assertEqual(self.attempts(), {"192.0.2.1": 1.0})


class TestWhenItFails(PushCase):
    def test_a_refused_login_costs_the_push_and_nothing_else(self):
        self.login_file.write_text("wrong")
        self.rows = [("load1", "", 0.5)]
        code, errors = self.collect()
        self.assertEqual(code, 0, "a failed push must not fail the sampling")
        self.assertIn("push", errors)
        self.assertIn("401", errors)
        self.assertNotIn("wrong", errors)
        with self.module.connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM samples").fetchone()[0], 1)

    def test_a_station_that_does_not_answer_is_said_and_survived(self):
        self.stub.stop()
        self.rows = [("load1", "", 0.5)]
        code, errors = self.collect()
        self.assertEqual(code, 0)
        self.assertIn("push", errors)

    def test_the_push_command_tells_no_station_from_a_failure(self):
        # The alert unit mails on anything but 0, and a node with no station
        # has nobody else to tell
        self.unconfigure()
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(self.module.main(["push"]), 3)

    def test_the_push_command_reports_its_failure_in_its_exit_status(self):
        self.stub.stop()
        self.rows = [("load1", "", 0.5)]
        self.collect("--no-push")
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(self.module.main(["push"]), 1)

    def test_the_password_is_never_in_the_output(self):
        self.rows = [("load1", "", 0.5)]
        code, errors = self.collect()
        self.assertNotIn(PASSWORD, errors)


class TestWithoutAStation(PushCase):
    def test_nothing_is_pushed_and_it_says_so_once(self):
        self.unconfigure()
        self.rows = [("load1", "", 0.5)]
        outputs = [self.collect()[1] for _ in range(3)]
        self.assertEqual(self.stub.requests, [])
        self.assertIn("station", outputs[0])
        self.assertEqual(outputs[1:], ["", ""], "the note repeats on every run")

    def test_it_says_so_again_after_a_station_came_and_went(self):
        self.unconfigure()
        self.rows = [("load1", "", 0.5)]
        self.collect()
        self.configure()
        self.collect()
        self.unconfigure()
        self.assertIn("station", self.collect()[1])

    def test_no_push_samples_without_pushing_and_without_a_word(self):
        self.rows = [("load1", "", 0.5)]
        code, errors = self.collect("--no-push")
        self.assertEqual((code, errors), (0, ""))
        self.assertEqual(self.stub.requests, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
