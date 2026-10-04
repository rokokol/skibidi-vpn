"""The report's node list, held to what the template promises.

Two promises live in report.toml.j2 and nowhere else. The master reads its own
store through its own API, the way it reads every node: one path, so the
deploy probe that proves it also proves the endpoint a dashboard will use. And
the pull's address is the registry's own `metrics_host` declaration, nothing
else: a node that has not declared one must fail the render, because the
template is the one place the pull's address could quietly fuse back into the
panel's listen field.
"""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

from jinja2 import Environment, StrictUndefined
from jinja2.exceptions import UndefinedError

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "roles" / "reporter" / "templates" / "report.toml.j2"


def render(hostvars: dict, inventory_hostname: str = "master", groups: dict | None = None) -> dict:
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
        metrics_api_port=9099,
        inventory_hostname=inventory_hostname,
        groups={"nodes": sorted(hostvars)} if groups is None else groups,
        hostvars=hostvars,
    )
    return tomllib.loads(text)


HOSTVARS = {
    "master": {"xui_listen_ip": "100.100.0.1", "metrics_host": "100.100.0.11"},
    "alpha": {"xui_listen_ip": "100.100.0.2", "metrics_host": "100.100.0.22"},
    "beta": {"xui_listen_ip": "100.100.0.3", "metrics_host": "100.100.0.33"},
}


class TestReportConfig(unittest.TestCase):
    def test_the_master_is_pulled_like_every_node(self):
        config = render(HOSTVARS)
        names = [node["name"] for node in config["nodes"]]
        self.assertEqual(sorted(names), ["alpha", "beta", "master"])
        self.assertEqual(len(names), len(set(names)), "a node is pulled twice")

    def test_a_master_outside_any_group_still_pulls_itself(self):
        # The VM test has no nodes group; the letter must still read the one
        # store that exists rather than send a letter about nobody
        config = render({"master": HOSTVARS["master"]}, groups={})
        self.assertEqual([node["name"] for node in config["nodes"]], ["master"])

    def test_the_address_is_the_registry_declaration(self):
        config = render(HOSTVARS)
        hosts = {node["name"]: node["host"] for node in config["nodes"]}
        self.assertEqual(hosts, {"master": "100.100.0.11", "alpha": "100.100.0.22",
                                 "beta": "100.100.0.33"})

    def test_a_node_without_a_declaration_fails_the_render(self):
        # The alternative — quietly borrowing the panel's listen address — is
        # exactly the coincidence this field exists to end
        for name in ("beta", "master"):
            with self.subTest(node=name):
                undeclared = dict(HOSTVARS, **{name: {"xui_listen_ip": "100.100.0.3"}})
                with self.assertRaises(UndefinedError):
                    render(undeclared)

    def test_the_pull_asks_the_port_the_nodes_listen_on(self):
        config = render(HOSTVARS)
        self.assertEqual(config["metrics"], {"port": 9099})

    def test_no_ssh_setting_survives(self):
        config = render(HOSTVARS)
        self.assertNotIn("ssh_user", config["paths"])
        self.assertNotIn("ssh_key", config["paths"])

    def test_the_panel_is_a_database_and_no_credential(self):
        # A url or a token here would mean the API is back, and with it the
        # rotation that knocks out every other holder of the CLI's token
        config = render(HOSTVARS)
        self.assertEqual(config["panel"], {"db": "/etc/x-ui/x-ui.db"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
