"""The push the nodes and the master send to the station's Pushgateway.

The library is shared by the collector, the reporter and the daily check, so
what it promises is held here once: the text it renders is accepted by a
parser as strict as the real one, the request goes to the one path the
station allows with the node's own login, and a refusal never carries the
password into a message that reaches a journal.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "roles" / "metrics" / "files"
sys.path.insert(0, str(LIB))

import skibidi_push as push  # noqa: E402
from pushgateway_stub import Refused, Stub, parse_exposition  # noqa: E402

# Punctuation on purpose: the login travels through base64 and a path, and
# neither may mangle a colon, a percent sign or an at sign
PASSWORD = "p:ss%w@rd/+="


class StubCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.login_file = self.dir / "rest-password"
        self.login_file.write_text(PASSWORD)
        self.stub = Stub("node-a", PASSWORD).start()
        self.addCleanup(self.stub.stop)

    def target(self, **overrides):
        values = {
            "base": f"http://127.0.0.1:{self.stub.port}",
            "user": "node-a",
            "password_file": str(self.login_file),
            "guard": None,
        }
        return {**values, **overrides}


class TestRender(unittest.TestCase):
    def test_a_family_round_trips_through_a_strict_parser(self):
        text = push.render([
            push.family("vpn_load1", "gauge", "One-minute load average", [({}, 0.25)]),
            push.family("vpn_fail2ban_banned_total", "counter", "Bans since the jail started",
                        [({"jail": "sshd"}, 412.0), ({"jail": "3x-ipl"}, 3.0)]),
        ])
        families = parse_exposition(text)
        self.assertEqual(families["vpn_load1"]["type"], "gauge")
        self.assertEqual(families["vpn_load1"]["samples"], [({}, 0.25)])
        self.assertEqual(families["vpn_fail2ban_banned_total"]["type"], "counter")
        self.assertEqual(
            sorted(families["vpn_fail2ban_banned_total"]["samples"], key=lambda pair: pair[1]),
            [({"jail": "3x-ipl"}, 3.0), ({"jail": "sshd"}, 412.0)],
        )
        self.assertTrue(families["vpn_load1"]["help"])

    def test_a_label_value_is_escaped_not_trusted(self):
        text = push.render([push.family("vpn_client_x", "gauge", "x",
                                        [({"client": 'a"b\\c\nd'}, 1.0)])])
        samples = parse_exposition(text)["vpn_client_x"]["samples"]
        self.assertEqual(len(samples), 1, "a quote or a newline in a label broke the line")
        self.assertEqual(samples[0][0]["client"], 'a\\"b\\\\c\\nd')

    def test_the_text_ends_with_a_newline(self):
        # The real parser refuses a body that stops mid-line
        self.assertTrue(push.render([push.family("vpn_a", "gauge", "a", [({}, 1)])]).endswith("\n"))

    def test_a_name_outside_the_prefix_is_refused_before_it_leaves(self):
        with self.assertRaises(ValueError):
            push.render([push.family("node_load1", "gauge", "x", [({}, 1)])])

    def test_the_one_name_the_station_alerts_on_is_allowed_without_the_prefix(self):
        text = push.render([push.family("node_problem", "gauge", "x", [({"key": "a"}, 1)])])
        self.assertEqual(parse_exposition(text)["node_problem"]["samples"], [({"key": "a"}, 1.0)])

    def test_no_other_name_escapes_the_prefix(self):
        for name in ("node_problems", "node_problem_total", "problem"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                push.render([push.family(name, "gauge", "x", [({}, 1)])])

    def test_a_bad_label_name_is_refused(self):
        with self.assertRaises(ValueError):
            push.render([push.family("vpn_a", "gauge", "x", [({"bad-name": "v"}, 1)])])

    def test_a_repeated_label_set_is_refused_here_not_by_the_station(self):
        with self.assertRaises(ValueError):
            push.render([push.family("vpn_a", "gauge", "x", [({"j": "a"}, 1), ({"j": "a"}, 2)])])

    def test_the_stub_parser_really_refuses_what_the_station_would(self):
        for bad in ("vpn_a 1", "load1 1\n", "vpn_a{x=1} 1\n", "# TYPE vpn_a bogus\n",
                    "vpn_a 1\nvpn_a 2\n"):
            with self.subTest(body=bad), self.assertRaises(Refused):
                parse_exposition(bad)


class TestValidateText(unittest.TestCase):
    """A file another program wrote is checked before it joins a body: the
    station refuses the whole body for one bad line, and the body carries the
    node's sign of life"""

    GOOD = "# HELP vpn_a x\n# TYPE vpn_a counter\nvpn_a{c=\"x\"} 1.0\n"

    def test_a_well_formed_file_passes(self):
        push.validate_text(self.GOOD, taken=set())

    def test_a_line_that_is_not_a_sample_is_refused(self):
        with self.assertRaises(ValueError):
            push.validate_text("vpn_a 1\nnot a sample\n", taken=set())

    def test_a_name_outside_the_prefix_is_refused(self):
        with self.assertRaises(ValueError):
            push.validate_text("load1 1\n", taken=set())

    def test_the_unprefixed_problem_name_is_not_for_another_program_to_write(self):
        with self.assertRaises(ValueError):
            push.validate_text("node_problem{key=\"a\"} 1\n", taken=set())

    def test_a_family_the_body_already_has_is_refused(self):
        with self.assertRaises(ValueError):
            push.validate_text(self.GOOD, taken={"vpn_a"})

    def test_a_file_that_stops_mid_line_is_refused(self):
        with self.assertRaises(ValueError):
            push.validate_text("vpn_a 1", taken=set())


class TestLatest(unittest.TestCase):
    def test_the_newest_row_of_each_series_wins(self):
        rows = [
            (1, "load1", "", 5.0),
            (3, "load1", "", 1.0),
            (2, "load1", "", 9.0),
            (2, "f2b_banned_now", "sshd", 4.0),
            (2, "f2b_banned_now", "recidive", 0.0),
        ]
        self.assertEqual(push.latest(rows), {
            ("load1", ""): (3, 1.0),
            ("f2b_banned_now", "sshd"): (2, 4.0),
            ("f2b_banned_now", "recidive"): (2, 0.0),
        })

    def test_no_rows_is_an_empty_answer(self):
        self.assertEqual(push.latest([]), {})


class TestTarget(unittest.TestCase):
    def test_nothing_configured_is_no_target(self):
        self.assertIsNone(push.target({}))
        self.assertIsNone(push.target({"SKIBIDI_PUSH_BASE": ""}))

    def test_the_environment_names_the_whole_target(self):
        found = push.target({
            "SKIBIDI_PUSH_BASE": "http://100.64.0.2:9091",
            "SKIBIDI_PUSH_USER": "node-a",
            "SKIBIDI_PUSH_PASSWORD_FILE": "/etc/skibidi/backup/rest-password",
            "SKIBIDI_PUSH_GUARD": "/usr/local/sbin/skibidi-backup target",
        })
        self.assertEqual(found["base"], "http://100.64.0.2:9091")
        self.assertEqual(found["user"], "node-a")
        self.assertEqual(found["password_file"], "/etc/skibidi/backup/rest-password")
        self.assertEqual(found["guard"], ["/usr/local/sbin/skibidi-backup", "target"])

    def test_a_half_configured_target_is_an_error_not_silence(self):
        with self.assertRaises(push.PushError):
            push.target({"SKIBIDI_PUSH_BASE": "http://100.64.0.2:9091"})


class TestPush(StubCase):
    FAMILIES = [push.family("vpn_load1", "gauge", "One-minute load average", [({}, 0.5)])]

    def test_the_push_goes_to_the_one_path_with_the_nodes_own_login(self):
        push.push(self.target(), self.FAMILIES)
        self.assertEqual(len(self.stub.requests), 1)
        request = self.stub.requests[0]
        self.assertEqual(request["status"], 200, request["reason"])
        self.assertEqual(request["path"], "/metrics/job/vpn/instance/node-a")
        self.assertEqual(request["user"], "node-a")
        self.assertEqual(parse_exposition(request["body"])["vpn_load1"]["samples"], [({}, 0.5)])

    def test_it_replaces_the_group_so_that_a_series_that_went_away_goes_away(self):
        # One writer owns the group. A problem that was solved is missing from
        # the next body, and only a replacing push takes it off the station
        push.push(self.target(), self.FAMILIES)
        self.assertEqual(self.stub.requests[0]["method"], "PUT")

    def test_a_refused_login_is_an_error_that_does_not_carry_the_password(self):
        self.login_file.write_text("wrong")
        with self.assertRaises(push.PushError) as caught:
            push.push(self.target(), self.FAMILIES)
        self.assertIn("401", str(caught.exception))
        self.assertNotIn("wrong", str(caught.exception))
        self.assertNotIn(PASSWORD, str(caught.exception))

    def test_the_instance_is_the_login_user_whatever_the_name(self):
        other = Stub("node b", PASSWORD).start()
        self.addCleanup(other.stop)
        push.push(self.target(base=f"http://127.0.0.1:{other.port}", user="node b"), self.FAMILIES)
        self.assertEqual(other.requests[0]["status"], 200, other.requests[0]["reason"])
        self.assertEqual(other.requests[0]["path"], "/metrics/job/vpn/instance/node%20b")

    def test_an_unreadable_password_file_is_an_error(self):
        with self.assertRaises(push.PushError):
            push.push(self.target(password_file=str(self.dir / "missing")), self.FAMILIES)
        self.assertEqual(self.stub.requests, [])

    def test_a_station_that_does_not_answer_is_an_error(self):
        # Bound and closed without ever serving, so the connection is refused
        dead = Stub("node-a", PASSWORD)
        port = dead.port
        dead.server.server_close()
        with self.assertRaises(push.PushError):
            push.push(self.target(base=f"http://127.0.0.1:{port}"), self.FAMILIES, timeout=2)

    def test_a_guard_that_refuses_stops_the_push_before_any_request(self):
        refuse = self.dir / "refuse"
        refuse.write_text("#!/bin/sh\necho 'plain HTTP outside the tunnel' >&2\nexit 1\n")
        refuse.chmod(0o755)
        with self.assertRaises(push.PushError) as caught:
            push.push(self.target(guard=[str(refuse)]), self.FAMILIES)
        self.assertIn("plain HTTP outside the tunnel", str(caught.exception))
        self.assertEqual(self.stub.requests, [])

    def test_a_guard_that_accepts_lets_the_push_through(self):
        accept = self.dir / "accept"
        accept.write_text("#!/bin/sh\nexit 0\n")
        accept.chmod(0o755)
        push.push(self.target(guard=[str(accept)]), self.FAMILIES)
        self.assertEqual(len(self.stub.requests), 1)

    def test_a_body_the_station_cannot_parse_is_an_error(self):
        # The library renders valid text, so this goes around it to prove the
        # refusal of the station reaches the caller as a failure
        with self.assertRaises(push.PushError) as caught:
            push.push_text(self.target(), "vpn_a 1")
        self.assertIn("400", str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
