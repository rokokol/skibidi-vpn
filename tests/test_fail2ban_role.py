"""The jails the fail2ban role writes: the fleet never bans itself, and a
client over the device limit is never held for a week as a repeat offender."""

from __future__ import annotations

import ast
import configparser
import re
import unittest

from test_push_units import defaults, render, tasks


def jails(**overrides) -> configparser.ConfigParser:
    values = dict(defaults("metrics", "fail2ban"), **overrides)
    # Ansible turns a default that renders to a list literal into a list, and
    # the helper renders it to text
    values["fail2ban_ignoreip"] = ast.literal_eval(values["fail2ban_ignoreip"])
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.read_string(render("fail2ban", "jail.local.j2", values))
    return parser


class TestIgnoreip(unittest.TestCase):
    def test_every_node_of_the_fleet_is_never_banned(self):
        ignored = jails(fail2ban_fleet_addresses=["198.51.100.4", "203.0.113.7"])["DEFAULT"]["ignoreip"].split()
        self.assertIn("198.51.100.4", ignored)
        self.assertIn("203.0.113.7", ignored)

    def test_the_tunnel_stays_ignored_beside_the_fleet(self):
        values = defaults("metrics", "fail2ban")
        ignored = jails(fail2ban_fleet_addresses=["198.51.100.4"])["DEFAULT"]["ignoreip"].split()
        for network in values["metrics_tunnel_ranges"]:
            self.assertIn(network, ignored)

    def test_the_fleet_is_asked_whole_even_under_a_limit(self):
        ask = [task for task in tasks("fail2ban") if task.get("name") == "Ask every node of the fleet for its public address"]
        self.assertEqual(len(ask), 1)
        self.assertEqual(ask[0]["loop"], "{{ groups['all'] }}")
        self.assertEqual(ask[0]["delegate_to"], "{{ item }}")
        self.assertTrue(ask[0]["run_once"])
        # A node that is down must not stop the deploy of another
        self.assertTrue(ask[0]["ignore_unreachable"])
        self.assertFalse(ask[0]["changed_when"])


class TestRecidive(unittest.TestCase):
    def test_a_ban_of_the_client_jail_is_not_counted_as_a_repeat_offence(self):
        recidive = jails()["recidive"]
        self.assertIn("3x-ipl", recidive["filter"])
        self.assertIn("recidive", recidive["filter"], "recidive must still skip its own bans")

    def test_without_the_client_jail_recidive_keeps_its_stock_filter(self):
        self.assertNotIn("filter", jails(fail2ban_ipl_enabled=False)["recidive"])

    def test_the_week_long_bans_of_clients_are_lifted(self):
        main = tasks("fail2ban")
        names = [task.get("name") for task in main]
        find = main[names.index("Find the clients recidive holds for the device limit alone")]
        lift = main[names.index("Lift those bans")]
        self.assertIn("client-only-bans 3x-ipl", find["ansible.builtin.script"]["cmd"])
        self.assertEqual(lift["ansible.builtin.command"]["argv"][:4], ["fail2ban-client", "set", "recidive", "unbanip"])
        self.assertIn("fail2ban_client_bans.stdout_lines", lift["loop"])
        self.assertIn("fail2ban_address_pattern", lift["loop"])
        # The jails have to be running with the new filter before a lifted
        # client is safe from being banned again at once
        self.assertGreater(names.index("Find the clients recidive holds for the device limit alone"),
                           names.index("Apply pending restarts before asking what is running"))

    def test_a_warning_the_node_prints_is_never_taken_for_an_address(self):
        # The script module runs on a terminal, so stderr arrives in stdout
        pattern = re.compile(defaults("metrics", "fail2ban")["fail2ban_address_pattern"])
        self.assertIsNone(pattern.match("sudo: unable to resolve host node-a: Name or service not known"))
        self.assertIsNotNone(pattern.match("198.51.100.7"))
        self.assertIsNotNone(pattern.match("2001:db8::7"))
        keep = [task for task in tasks("fail2ban") if task.get("name") == "Keep the addresses the fleet gave"]
        self.assertIn("fail2ban_address_pattern", keep[0]["ansible.builtin.set_fact"]["fail2ban_fleet_addresses"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
