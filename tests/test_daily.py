"""The daily check: one mail, only when something is still open.

The node's real metrics API serves a throwaway store on loopback, the last
result of `skibidi-check` is a file, and the master's panel part is a stub
command, so what runs here is the daily check's own code from the files it
reads to the lines it prints. A failure of its own mail path is the alert
unit's business and is proven in the VM scenario.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "roles" / "metrics" / "files"
os.environ["SKIBIDI_LIB"] = str(LIB)
sys.path.insert(0, str(LIB))


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


daily = load("skibidi_daily", ROOT / "roles" / "checker" / "files" / "skibidi-daily.py")

SECOND = 1_000_000
DAY = 86400


class DailyCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.db = self.dir / "metrics.db"
        os.environ["SKIBIDI_METRICS_DB"] = str(self.db)
        self.addCleanup(os.environ.pop, "SKIBIDI_METRICS_DB", None)
        # Loaded after the variable is set: the module reads its store's path once
        self.metrics = load("skibidi_metrics", LIB / "skibidi-metrics.py")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.metrics.handler_for(self.db))
        threading.Thread(target=self.server.serve_forever, args=(0.01,), daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.result = self.dir / "failures"
        self.report_bin = self.dir / "skibidi-report"
        self.environ = {
            "SKIBIDI_API_URL": f"http://127.0.0.1:{self.server.server_address[1]}",
            "SKIBIDI_CHECK_RESULT": str(self.result),
            "SKIBIDI_CHECK_MAX_AGE_HOURS": "2",
            "SKIBIDI_REPORT_BIN": str(self.report_bin),
        }
        self.quiet_node()
        self.result.write_text("")

    def quiet_node(self, overrides=None):
        now = time.time()
        values = {
            ("disk_used_ratio", ""): 0.4,
            ("disk_total_bytes", ""): 50e9,
            ("established_no_timer", ""): 2.0,
            ("reboot_required", ""): 0.0,
            ("pkg_updates", ""): 0.0,
            ("timer_last_fired", "xray-geodata-update.timer"): now - DAY,
        }
        values.update(overrides or {})
        stamp = int((now - 60) * SECOND)
        with self.metrics.connect() as connection:
            connection.execute("DELETE FROM samples")
            connection.executemany(
                "INSERT INTO samples (ts_us, metric, detail, value) VALUES (?, ?, ?, ?)",
                [(stamp, metric, detail, value) for (metric, detail), value in values.items()],
            )
            connection.execute("INSERT OR REPLACE INTO state VALUES ('collected_through_us', ?)",
                               (str(stamp),))

    def panel_stub(self, lines=(), rc=0):
        body = "".join(f"printf '%s\\n' '{line}'\n" for line in lines)
        self.report_bin.write_text(f"#!/bin/sh\n{body}exit {rc}\n")
        self.report_bin.chmod(0o755)

    def run_daily(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = daily.main([], self.environ)
        lines = out.getvalue().splitlines()
        return code, lines, [line[5:] for line in lines if line.startswith("FAIL ")]


class TestRunWithoutItsSettings(DailyCase):
    def test_a_run_that_lacks_its_settings_says_so_and_is_neither_clear_nor_open(self):
        # Exit 1 means "something is open", which is also what a traceback
        # exits with. Missing settings must not look like either answer
        self.environ.pop("SKIBIDI_CHECK_RESULT")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = daily.main([], self.environ)
        self.assertEqual(code, 2)
        self.assertIn("SKIBIDI_CHECK_RESULT", err.getvalue())
        self.assertEqual(out.getvalue(), "")


class TestNothingOpen(DailyCase):
    def test_a_quiet_node_is_silent_in_the_way_that_sends_no_mail(self):
        code, lines, failures = self.run_daily()
        self.assertEqual((code, failures), (0, []))
        self.assertTrue(lines, "the journal should still say that it looked")

    def test_a_node_without_a_panel_asks_no_panel_question(self):
        # Only the master has the reporter; a missing command is no problem
        self.assertFalse(self.report_bin.exists())
        self.assertEqual(self.run_daily()[0], 0)


class TestWhatIsListed(DailyCase):
    def test_the_failures_the_last_check_left_are_listed(self):
        self.result.write_text("nginx is not running\nufw is not active\n")
        code, _lines, failures = self.run_daily()
        self.assertEqual(code, 1)
        self.assertEqual(failures, ["nginx is not running", "ufw is not active"])

    def test_non_urgent_items_are_listed_too(self):
        self.quiet_node({
            ("reboot_required", ""): 1.0,
            ("pkg_updates", ""): 12.0,
            ("timer_last_fired", "xray-geodata-update.timer"): time.time() - 20 * DAY,
        })
        _code, _lines, failures = self.run_daily()
        text = "\n".join(failures)
        self.assertIn("reboot", text)
        self.assertIn("12", text)
        self.assertIn("geodata", text)

    def test_everything_open_comes_in_one_list_not_the_worst_one(self):
        self.result.write_text("nginx is not running\n")
        self.quiet_node({("reboot_required", ""): 1.0})
        self.panel_stub(["node node-b is offline as the panel sees it"])
        code, _lines, failures = self.run_daily()
        self.assertEqual(code, 1)
        self.assertEqual(len(failures), 3, failures)

    def test_the_panel_part_of_the_master_is_included(self):
        self.panel_stub(["client Mo expires in 3 days"])
        _code, _lines, failures = self.run_daily()
        self.assertEqual(failures, ["client Mo expires in 3 days"])

    def test_a_panel_command_that_crashes_is_itself_a_problem(self):
        self.panel_stub(rc=3)
        code, _lines, failures = self.run_daily()
        self.assertEqual(code, 1)
        self.assertEqual(len(failures), 1)
        self.assertIn("panel", failures[0])

    def test_an_item_that_stays_open_comes_again_the_next_day(self):
        self.quiet_node({("reboot_required", ""): 1.0})
        first = self.run_daily()
        second = self.run_daily()
        self.assertEqual(first[2], second[2])
        self.assertEqual(second[0], 1)

    def test_the_last_line_counts_what_was_listed(self):
        # The alert mail takes the last line as its subject
        self.result.write_text("a\nb\n")
        _code, lines, failures = self.run_daily()
        self.assertIn(f"{len(failures)} unresolved", lines[-1])


class TestWhatCannotBeKnown(DailyCase):
    def test_a_missing_result_is_open_not_assumed_good(self):
        self.result.unlink()
        code, _lines, failures = self.run_daily()
        self.assertEqual(code, 1)
        self.assertIn("skibidi-check", failures[0])

    def test_a_stale_result_is_open_and_does_not_replay_old_failures(self):
        self.result.write_text("nginx is not running\n")
        old = time.time() - 5 * 3600
        os.utime(self.result, (old, old))
        _code, _lines, failures = self.run_daily()
        self.assertEqual(len(failures), 1)
        self.assertIn("skibidi-check", failures[0])
        self.assertNotIn("nginx", failures[0])

    def test_a_metrics_api_that_does_not_answer_is_open(self):
        self.environ["SKIBIDI_API_URL"] = "http://127.0.0.1:9"
        code, _lines, failures = self.run_daily()
        self.assertEqual(code, 1)
        self.assertEqual(len(failures), 1)
        self.assertIn("metrics API", failures[0])

    def test_an_error_status_is_an_open_item_that_says_why(self):
        # No store at all: the API answers 503, and that must not read as a
        # quiet node
        self.db.unlink()
        code, _lines, failures = self.run_daily()
        self.assertEqual(code, 1)
        self.assertEqual(len(failures), 1)
        self.assertIn("503", failures[0])

    def test_a_cut_answer_is_refused_rather_than_read_as_the_newest_rows(self):
        # The rows come oldest first, so a cut drops exactly the newest ones
        self.metrics.SAMPLES_LIMIT = 2
        code, _lines, failures = self.run_daily()
        self.assertEqual(code, 1)
        self.assertIn("cut", "\n".join(failures))

    def test_an_empty_store_is_a_collector_that_never_ran(self):
        self.db.unlink()
        with self.metrics.connect():
            pass
        code, _lines, failures = self.run_daily()
        self.assertEqual(code, 1)
        self.assertIn("collector", "\n".join(failures))


if __name__ == "__main__":
    unittest.main(verbosity=2)
