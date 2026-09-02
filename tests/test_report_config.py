"""The report's node list, held to what the template promises.

Two promises live in report.toml.j2 and nowhere else. The master never pulls
from itself: a self-pull would work — the guard would permit it, the store
would answer — and from that day on nobody could tell the local read from the
remote path it silently duplicates. And the pull's address is the registry's
own `metrics_host` declaration, nothing else: a node that has not declared one
must fail the render, because the template is the one place the pull's address
could quietly fuse back into the panel's listen field.
"""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

from jinja2 import Environment, StrictUndefined
from jinja2.exceptions import UndefinedError

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "roles" / "reporter" / "templates" / "report.toml.j2"


def render(hostvars: dict, inventory_hostname: str = "master") -> dict:
    env = Environment(trim_blocks=True, undefined=StrictUndefined)
    text = env.from_string(TEMPLATE.read_text()).render(
        ansible_managed="rendered by the test",
        reporter_timezone="Europe/Moscow",
        reporter_hour=9,
        reporter_weekday="monday",
        reporter_weekday_index={"monday": 0},
        reporter_to="fleet@example.invalid",
        reporter_panel_db="/etc/x-ui/x-ui.db",
        reporter_state_dir="/var/lib/skibidi-report",
        reporter_sendmail="/usr/sbin/sendmail",
        metrics_export_user="skibidi-metrics",
        inventory_hostname=inventory_hostname,
        groups={"nodes": sorted(hostvars)},
        hostvars=hostvars,
    )
    return tomllib.loads(text)


HOSTVARS = {
    "master": {"xui_listen_ip": "100.100.0.1"},
    "alpha": {"xui_listen_ip": "100.100.0.2", "metrics_host": "100.100.0.22"},
    "beta": {"xui_listen_ip": "100.100.0.3", "metrics_host": "100.100.0.33"},
}


class TestReportConfig(unittest.TestCase):
    def test_the_master_never_pulls_from_itself(self):
        config = render(HOSTVARS)
        names = [node["name"] for node in config["nodes"]]
        self.assertNotIn("master", names)
        self.assertEqual(names, ["alpha", "beta"])

    def test_the_address_is_the_registry_declaration(self):
        config = render(HOSTVARS)
        hosts = {node["name"]: node["host"] for node in config["nodes"]}
        self.assertEqual(hosts["alpha"], "100.100.0.22")
        self.assertEqual(hosts["beta"], "100.100.0.33")

    def test_a_node_without_a_declaration_fails_the_render(self):
        # The alternative — quietly borrowing the panel's listen address — is
        # exactly the coincidence this field exists to end
        undeclared = dict(HOSTVARS, beta={"xui_listen_ip": "100.100.0.3"})
        with self.assertRaises(UndefinedError):
            render(undeclared)

    def test_the_pull_arrives_as_the_export_account(self):
        config = render(HOSTVARS)
        self.assertEqual(config["paths"]["ssh_user"], "skibidi-metrics")

    def test_the_panel_is_a_database_and_no_credential(self):
        # A url or a token here would mean the API is back, and with it the
        # rotation that knocks out every other holder of the CLI's token
        config = render(HOSTVARS)
        self.assertEqual(config["panel"], {"db": "/etc/x-ui/x-ui.db"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
