"""The master's reporter, proven on synthetic data: no panel, no fleet, no VM.

It does two things. It writes the panel's traffic as a file the collector adds
to its own push, and it lists the open items only the panel knows. It mails
nothing and keeps no history: the weekly letter is gone, and the numbers are
on the station's dashboard.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "roles" / "metrics" / "files"
os.environ["SKIBIDI_LIB"] = str(LIB)
sys.path.insert(0, str(LIB))

from pushgateway_stub import parse_exposition  # noqa: E402

SCRIPT = ROOT / "roles" / "reporter" / "files" / "skibidi-report.py"
specification = importlib.util.spec_from_file_location("skibidi_report", SCRIPT)
report = importlib.util.module_from_spec(specification)
sys.modules["skibidi_report"] = report
specification.loader.exec_module(report)

UUID = "11111111-2222-3333-4444-555555555555"


def make_panel_db(extra_inbounds: bool = False) -> Path:
    path = Path(tempfile.mkdtemp(prefix="skibidi-panel-")) / "x-ui.db"
    with sqlite3.connect(path) as db:
        db.executescript(f"""
            CREATE TABLE inbounds (id INTEGER PRIMARY KEY, up INTEGER, down INTEGER,
                remark TEXT, enable INTEGER, port INTEGER, protocol TEXT,
                settings TEXT, node_id INTEGER);
            CREATE TABLE client_traffics (id INTEGER PRIMARY KEY, inbound_id INTEGER,
                email TEXT, up INTEGER, down INTEGER, total INTEGER,
                expiry_time INTEGER, enable INTEGER, last_online INTEGER);
            CREATE TABLE nodes (id INTEGER PRIMARY KEY, name TEXT, remark TEXT,
                status TEXT, last_heartbeat INTEGER, latency_ms INTEGER,
                cpu_pct REAL, mem_pct REAL, panel_version TEXT, xray_version TEXT);
            INSERT INTO inbounds VALUES (1, 10, 20, 'SE-exit', 1, 443, 'vless',
                '{{"clients": [{{"id": "{UUID}", "email": "Grandmother", "subId": "abcdef"}}]}}', NULL);
            INSERT INTO client_traffics VALUES (1, 1, 'Grandmother', 5, 7, 100, 0, 1, 1735680000000);
            INSERT INTO nodes VALUES (1, 'node-b', '', 'online', 1700000000, 42, 1.0, 20.0, '3.7.0', '25.1.1');
        """)
        if extra_inbounds:
            db.executescript("""
                INSERT INTO inbounds VALUES (2, 1, 2, 'SE-exit', 1, 8443, 'trojan',
                    '{"clients": []}', 3);
                INSERT INTO client_traffics VALUES (2, 2, 'Mo', 100, 200, 0, 0, 1, 0);
            """)
    return path


class TestLabels(unittest.TestCase):
    def test_the_operator_reads_their_own_labels_in_clear(self):
        # The dashboard is the fleet owner's; masking their family's names
        # from them protects nobody. The credential half is what stays out
        self.assertEqual(report.client_label("Grandmother"), "Grandmother")
        self.assertEqual(report.client_label(None), "")


class TestPanelDatabase(unittest.TestCase):
    """The panel is read through its database, so the shape everything else
    expects is produced here and nowhere else; these hold that shape against a
    synthetic database with the panel's own column names."""

    def test_inbounds_come_out_in_the_shape_the_reporter_reads(self):
        db = report.open_panel_db(str(make_panel_db()))
        inbounds = report.db_inbounds(db)
        self.assertEqual(inbounds[0]["remark"], "SE-exit")
        self.assertEqual(inbounds[0]["clientStats"][0]["email"], "Grandmother")
        self.assertEqual(report.client_traffic(inbounds[0]["clientStats"][0]), (5, 7, 1735680000000))

    def test_nodes_and_their_state_need_no_token(self):
        db = report.open_panel_db(str(make_panel_db()))
        nodes = report.db_nodes(db)
        self.assertEqual(nodes[0]["name"], "node-b")
        self.assertEqual(nodes[0]["status"], "online")

    def test_a_panel_without_node_mode_is_an_empty_fleet_not_an_error(self):
        path = make_panel_db()
        with sqlite3.connect(path) as db:
            db.execute("DROP TABLE nodes")
        self.assertEqual(report.db_nodes(report.open_panel_db(str(path))), [])

    def test_the_database_is_opened_read_only(self):
        db = report.open_panel_db(str(make_panel_db()))
        with self.assertRaises(sqlite3.OperationalError):
            db.execute("DELETE FROM inbounds")

    def test_a_missing_database_is_an_error_not_an_empty_fleet(self):
        with self.assertRaises(report.PanelError):
            report.open_panel_db("/nonexistent/x-ui.db")


class TestGatherPanel(unittest.TestCase):
    def test_nodes_and_clients_come_out_in_the_shape_the_rules_read(self):
        config = {"panel": {"db": str(make_panel_db())}}
        panel = report.gather_panel(config, 1_790_000_000 * 1_000_000)
        self.assertEqual(panel["nodes"], [{"name": "node-b", "online": True}])
        client = panel["clients"][0]
        self.assertEqual(client["label"], "Grandmother")
        self.assertTrue(client["enable"])
        self.assertAlmostEqual(client["cap_share"], 12 / 100)
        self.assertIsNone(client["expires_days"])


class TestTraffic(unittest.TestCase):
    def families(self, db):
        connection = report.open_panel_db(str(db))
        return report.traffic_families(report.panel_traffic(report.db_inbounds(connection)))

    def by_name(self, families):
        return {item["name"]: item for item in families}

    def test_traffic_is_per_inbound_and_per_client_in_both_directions(self):
        families = self.by_name(self.families(make_panel_db()))
        inbound = families["vpn_inbound_traffic_bytes_total"]
        client = families["vpn_client_traffic_bytes_total"]
        self.assertEqual(inbound["type"], "counter")
        self.assertEqual(sorted(inbound["samples"], key=lambda pair: pair[0]["direction"]),
                         [({"inbound": "SE-exit", "direction": "down"}, 20.0),
                          ({"inbound": "SE-exit", "direction": "up"}, 10.0)])
        self.assertEqual(sorted(client["samples"], key=lambda pair: pair[0]["direction"]),
                         [({"client": "Grandmother", "direction": "down"}, 7.0),
                          ({"client": "Grandmother", "direction": "up"}, 5.0)])

    def test_two_inbounds_with_one_remark_add_up_instead_of_colliding(self):
        # The station refuses a body that repeats a label set, and the panel
        # lets two inbounds on two nodes share a remark
        families = self.by_name(self.families(make_panel_db(extra_inbounds=True)))
        down = [pair for pair in families["vpn_inbound_traffic_bytes_total"]["samples"]
                if pair[0]["direction"] == "down"]
        self.assertEqual(down, [({"inbound": "SE-exit", "direction": "down"}, 22.0)])

    def test_no_credential_is_in_what_leaves(self):
        text = report.skibidi_push.render(self.families(make_panel_db()))
        for secret in (UUID, "abcdef", "subId"):
            self.assertNotIn(secret, text)

    def test_every_name_is_prefixed(self):
        for item in self.families(make_panel_db()):
            self.assertTrue(item["name"].startswith("vpn_"))


class CommandCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.file = self.dir / "traffic.prom"
        saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(saved)))
        os.environ["SKIBIDI_PUSH_TEXTFILE"] = str(self.file)
        self.config = {"panel": {"db": str(make_panel_db())}}

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = report.main(list(argv), self.config)
        return code, out.getvalue(), err.getvalue()


class TestTrafficCommand(CommandCase):
    def test_the_traffic_is_written_for_the_collector_to_add_to_its_push(self):
        self.assertEqual(self.run_main("traffic"), (0, "", ""))
        families = parse_exposition(self.file.read_text())
        self.assertIn("vpn_client_traffic_bytes_total", families)
        self.assertIn("vpn_inbound_traffic_bytes_total", families)

    def test_the_file_appears_whole_or_not_at_all(self):
        self.run_main("traffic")
        self.assertEqual([path.name for path in self.dir.iterdir()], ["traffic.prom"])

    def test_a_panel_with_no_traffic_yet_leaves_no_file(self):
        self.run_main("traffic")
        with sqlite3.connect(self.config["panel"]["db"]) as db:
            db.execute("DELETE FROM inbounds")
            db.execute("DELETE FROM client_traffics")
        self.assertEqual(self.run_main("traffic"), (0, "", ""))
        self.assertFalse(self.file.exists(), "an old file would be pushed as if it were current")

    def test_a_panel_that_does_not_answer_fails_and_removes_the_old_file(self):
        self.run_main("traffic")
        self.config["panel"]["db"] = "/nonexistent/x-ui.db"
        code, _out, err = self.run_main("traffic")
        self.assertEqual(code, 1)
        self.assertIn("panel", err)
        self.assertFalse(self.file.exists())

    def test_the_command_pushes_nothing_itself(self):
        # The collector owns the group; a second writer would be the stale
        # series the single writer exists to prevent
        self.assertNotIn("skibidi_push.push(", SCRIPT.read_text())


class TestProblemsCommand(CommandCase):
    def test_a_quiet_panel_prints_nothing(self):
        self.assertEqual(self.run_main("problems"), (0, "", ""))

    def test_an_offline_node_is_one_line(self):
        with sqlite3.connect(self.config["panel"]["db"]) as db:
            db.execute("UPDATE nodes SET status = 'offline'")
        code, out, _err = self.run_main("problems")
        self.assertEqual(code, 0)
        self.assertEqual(len(out.splitlines()), 1)
        self.assertIn("node-b", out)

    def test_a_panel_that_does_not_answer_is_itself_a_problem_not_a_crash(self):
        self.config["panel"]["db"] = "/nonexistent/x-ui.db"
        code, out, _err = self.run_main("problems")
        self.assertEqual(code, 0)
        self.assertIn("panel", out)


class TestWhatIsGone(unittest.TestCase):
    def test_the_letter_and_its_snapshots_are_not_commands_any_more(self):
        for command in ("send", "snapshot", "probe", "push"):
            with self.subTest(command=command):
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    self.assertEqual(report.main([command], {"panel": {"db": "/nonexistent"}}), 2)

    def test_the_script_mails_nothing(self):
        text = SCRIPT.read_text()
        for word in ("sendmail", "EmailMessage", "snapshot"):
            self.assertNotIn(word, text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
