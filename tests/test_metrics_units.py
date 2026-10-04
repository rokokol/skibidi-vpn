"""The systemd units that put the metrics API on the tailnet, and nowhere else.

The API has no authentication: who can reach it is decided entirely by the
socket unit, and what a request can do once it arrives by the service unit.
Both are rendered here from the role's own defaults and held to the security
properties they promise. The deploy and the checker prove the same properties
on a running node; this suite is what turns red on a laptop first.
"""

from __future__ import annotations

import configparser
import unittest
from pathlib import Path

import yaml
from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "roles" / "metrics"


def defaults() -> dict:
    values = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    # The interface default reads the firewall role's variable, which Ansible
    # resolves lazily; the test hands it the firewall's own default
    values["firewall_tunnel_interface"] = yaml.safe_load(
        (ROOT / "roles" / "firewall" / "defaults" / "main.yml").read_text()
    )["firewall_tunnel_interface"]
    env = Environment(undefined=StrictUndefined)
    for _ in range(3):
        values = {
            key: env.from_string(value).render(values) if isinstance(value, str) else value
            for key, value in values.items()
        }
    return values


def render(name: str, values: dict) -> configparser.ConfigParser:
    env = Environment(trim_blocks=True, undefined=StrictUndefined)
    text = env.from_string((ROLE / "templates" / name).read_text()).render(
        ansible_managed="rendered by the test", **values
    )
    # Not strict: systemd reads a repeated key such as SystemCallFilter= as a
    # list, and the last line of one is enough for what is asserted here
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    parser.read_string(text)
    return parser


class TestSocket(unittest.TestCase):
    def setUp(self):
        self.values = defaults()
        self.unit = render("skibidi-metrics-api.socket.j2", self.values)
        self.socket = self.unit["Socket"]

    def test_the_socket_is_bound_to_the_tunnel_interface(self):
        self.assertEqual(self.values["metrics_api_interface"], "tailscale0")
        self.assertEqual(self.socket["BindToDevice"], "tailscale0")

    def test_it_listens_on_the_api_port_for_both_families(self):
        self.assertEqual(self.socket["ListenStream"], str(self.values["metrics_api_port"]))
        self.assertEqual(self.socket["BindIPv6Only"], "both")

    def test_only_tunnel_sources_are_admitted(self):
        # The same declaration the old SSH key's from= was pinned to
        self.assertEqual(self.socket["IPAddressDeny"], "any")
        self.assertEqual(self.socket["IPAddressAllow"].split(),
                         ["localhost", *self.values["metrics_tunnel_ranges"]])

    def test_each_connection_gets_its_own_bounded_process(self):
        self.assertEqual(self.socket["Accept"], "yes")
        self.assertGreater(int(self.socket["MaxConnections"]), 0)

    def test_it_starts_whenever_the_interface_appears(self):
        # tailscaled recreates its interface on every restart, and BindsTo
        # stops the socket with it; only the device's wants bring it back
        self.assertEqual(self.unit["Install"]["WantedBy"], "sys-subsystem-net-devices-tailscale0.device")

    def test_a_host_without_a_tunnel_interface_listens_from_boot(self):
        # The loopback interface has no device unit, so a socket hung on one
        # would never start; the VM test runs this way
        unit = render("skibidi-metrics-api.socket.j2", dict(self.values, metrics_api_interface=""))
        self.assertNotIn("BindToDevice", unit["Socket"])
        self.assertEqual(unit["Install"]["WantedBy"], "sockets.target")


class TestService(unittest.TestCase):
    def setUp(self):
        self.values = defaults()
        self.service = render("skibidi-metrics-api@.service.j2", self.values)["Service"]

    def test_it_runs_as_a_dynamic_user_that_can_only_read_the_store(self):
        self.assertEqual(self.service["DynamicUser"], "yes")
        self.assertEqual(self.service["SupplementaryGroups"], self.values["metrics_reader_group"])
        # A static account of the same name makes systemd use it instead of
        # allocating a dynamic one
        self.assertNotEqual(self.service["User"], self.values["metrics_reader_group"])
        self.assertNotEqual(self.service["User"], "skibidi-metrics")

    def test_the_filesystem_is_read_only(self):
        self.assertEqual(self.service["ProtectSystem"], "strict")
        self.assertIn(self.values["metrics_db_dir"], self.service["ReadOnlyPaths"].split())
        for key in ("ReadWritePaths", "StateDirectory", "LogsDirectory", "CacheDirectory"):
            self.assertNotIn(key, self.service)

    def test_no_network_but_the_connection_it_was_handed(self):
        self.assertEqual(self.service["PrivateNetwork"], "yes")
        self.assertEqual(self.service["StandardInput"], "socket")

    def test_a_traceback_goes_to_the_journal_not_to_the_client(self):
        self.assertEqual(self.service["StandardError"], "journal")

    def test_it_holds_no_capability_and_cannot_run_long(self):
        self.assertEqual(self.service["CapabilityBoundingSet"], "")
        self.assertIn("RuntimeMaxSec", self.service)

    def test_it_serves_rather_than_collects(self):
        self.assertTrue(self.service["ExecStart"].endswith(" serve"))


class TestLegacyCleanup(unittest.TestCase):
    """A deploy on a node the SSH export was installed on removes all of it."""

    def setUp(self):
        self.tasks = yaml.safe_load((ROLE / "tasks" / "legacy-ssh-export.yml").read_text())

    def modules(self, module: str) -> list[dict]:
        return [task[module] for task in self.tasks if module in task]

    def test_the_export_account_is_removed_without_its_home(self):
        # Its home is the store directory: remove: true would delete the
        # metrics with the account
        users = self.modules("ansible.builtin.user")
        self.assertEqual([(u["name"], u["state"]) for u in users], [("skibidi-metrics", "absent")])
        self.assertFalse(users[0].get("remove", False))

    def test_the_key_material_is_removed(self):
        paths = {task["path"] for task in self.modules("ansible.builtin.file") if task.get("state") == "absent"}
        for path in ("/root/.ssh/skibidi-report", "/root/.ssh/skibidi-report.pub",
                     "{{ metrics_db_dir }}/.ssh"):
            self.assertIn(path, paths)

    def test_the_cleanup_is_part_of_the_role(self):
        main = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
        included = [task.get("ansible.builtin.include_tasks") or task.get("ansible.builtin.import_tasks")
                    for task in main]
        self.assertIn("legacy-ssh-export.yml", included)


if __name__ == "__main__":
    unittest.main(verbosity=2)
