"""The checker's metrics API section, run against stubbed system tools.

The API has no authentication, so the checker is what notices when the
boundaries around it drift: a listener off the tunnel, a firewall rule for its
port, a store others can read, the old SSH account still present. Each check is
run here once healthy and once with the one thing it watches broken, because a
check that has only ever been green proves nothing.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from jinja2 import Environment

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "roles" / "checker" / "templates" / "skibidi-check.j2"

START = "# --- the metrics API"
END = "# --- WARP"

# Each tool answers from an environment variable, so a scenario is a dict
STUBS = {
    "systemctl": 'exit "${STUB_SOCKET_RC:-0}"',
    "ss": 'printf "%b" "${STUB_SS:-}"',
    "ufw": 'printf "%b" "${STUB_UFW:-}"',
    "curl": 'printf "%s" "${STUB_CURL:-}"; exit "${STUB_CURL_RC:-0}"',
    "getent": 'exit "${STUB_GETENT_RC:-2}"',
    "stat": 'case "$3" in *metrics.db) printf "%s\\n" "${STUB_DB_MODE}" ;; *) printf "%s\\n" "${STUB_DIR_MODE}" ;; esac',
    "find": 'printf "%b" "${STUB_FIND:-}"',
}

HEALTHY = {
    "STUB_SS": "LISTEN 0 128 *%tailscale0:9099 *:*\\n",
    "STUB_UFW": "Status: active\\n\\nTo Action From\\n22/tcp ALLOW Anywhere\\n"
                "Anywhere on tailscale0 ALLOW Anywhere\\n",
    "STUB_CURL": '{"collected_through_us":1,"status":"ok"}',
    "STUB_DIR_MODE": "2750:root:skibidi-metrics",
    "STUB_DB_MODE": "640:root:skibidi-metrics",
}


def section(**overrides) -> str:
    values = {
        "metrics_api_port": 9099,
        "metrics_api_interface": "tailscale0",
        "firewall_tunnel_interface": "tailscale0",
        "metrics_host": "100.100.0.2",
        "metrics_db_dir": "/var/lib/skibidi-metrics",
        "metrics_reader_group": "skibidi-metrics",
        "metrics_tunnel_ranges": ["100.64.0.0/10"],
        "group_names": [],
        **overrides,
    }
    # Only the section is rendered, so the rest of the script's variables are
    # not this test's business
    source = TEMPLATE.read_text()
    source = source[source.index(START):source.index(END)]
    return Environment(trim_blocks=True).from_string(source).render(**values)


class TestMetricsChecks(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.bin = Path(tmp.name)
        for name, body in STUBS.items():
            path = self.bin / name
            path.write_text(f"#!/bin/sh\n{body}\n")
            path.chmod(0o755)

    def run_checks(self, overrides=None, env=None):
        script = (
            "failures=0\n"
            "fail() { printf 'FAIL %s\\n' \"$*\"; failures=$((failures + 1)); }\n"
            "ok() { printf 'ok   %s\\n' \"$*\"; }\n"
            + section(**(overrides or {}))
            + '\nexit "$failures"\n'
        )
        environment = {**os.environ, **HEALTHY, **(env or {})}
        environment["PATH"] = f"{self.bin}:{environment['PATH']}"
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                                env=environment, check=False)
        self.assertEqual(result.stderr, "")
        return result.returncode, [line for line in result.stdout.splitlines() if line.startswith("FAIL")]

    def assert_one_failure(self, needle, env=None, overrides=None):
        failures, lines = self.run_checks(overrides, env)
        self.assertEqual(failures, 1, lines)
        self.assertIn(needle, lines[0])

    def test_a_healthy_node_passes(self):
        self.assertEqual(self.run_checks(), (0, []))

    def test_an_inactive_socket_fails(self):
        self.assert_one_failure("socket is not active", {"STUB_SOCKET_RC": "3"})

    def test_a_listener_on_every_interface_fails(self):
        self.assert_one_failure("also listens on *:9099", {"STUB_SS": "LISTEN 0 128 *:9099 *:*\\n"})

    def test_a_listener_beside_the_tunnel_one_fails(self):
        self.assert_one_failure("also listens", {
            "STUB_SS": "LISTEN 0 128 *%tailscale0:9099 *:*\\nLISTEN 0 128 0.0.0.0:9099 0.0.0.0:*\\n"})

    def test_no_listener_at_all_fails(self):
        self.assert_one_failure("nothing listens", {"STUB_SS": ""})

    def test_a_host_without_a_tunnel_interface_only_needs_a_listener(self):
        failures, lines = self.run_checks({"metrics_api_interface": ""},
                                          {"STUB_SS": "LISTEN 0 128 *:9099 *:*\\n"})
        self.assertEqual((failures, lines), (0, []))

    def test_a_public_firewall_rule_for_the_port_fails(self):
        for rule in ("9099/tcp ALLOW Anywhere", "9099 ALLOW Anywhere", "9099/tcp (v6) ALLOW Anywhere (v6)"):
            with self.subTest(rule=rule):
                self.assert_one_failure("admits port 9099 off the tunnel",
                                        {"STUB_UFW": HEALTHY["STUB_UFW"] + rule + "\\n"})

    def test_a_tunnel_scoped_rule_for_the_port_passes(self):
        failures, _ = self.run_checks(env={
            "STUB_UFW": HEALTHY["STUB_UFW"] + "9099/tcp on tailscale0 ALLOW Anywhere\\n"})
        self.assertEqual(failures, 0)

    def test_an_api_that_does_not_answer_fails(self):
        self.assert_one_failure("does not answer healthy", {"STUB_CURL": "", "STUB_CURL_RC": "7"})

    def test_an_api_that_answers_unhealthy_fails(self):
        self.assert_one_failure("does not answer healthy", {"STUB_CURL": '{"status":"starting"}'})

    def test_a_store_others_can_read_fails(self):
        self.assert_one_failure("metric store", {"STUB_DB_MODE": "644:root:skibidi-metrics"})
        self.assert_one_failure("metric store", {"STUB_FIND": "/var/lib/skibidi-metrics/metrics.db-wal\\n"})
        self.assert_one_failure("metric store", {"STUB_DIR_MODE": "2750:root:root"})

    def test_the_old_export_account_fails(self):
        self.assert_one_failure("old metrics export account", {"STUB_GETENT_RC": "0"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
