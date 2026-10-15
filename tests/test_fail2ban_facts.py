"""What the fail2ban role asks a node before it writes the jails.

The node's public address goes into every node's ignoreip, so the fleet never
bans itself.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "roles" / "fail2ban" / "files" / "skibidi-fail2ban-facts.py"
spec = importlib.util.spec_from_file_location("skibidi_fail2ban_facts", SCRIPT)
facts = importlib.util.module_from_spec(spec)
sys.modules["skibidi_fail2ban_facts"] = facts
spec.loader.exec_module(facts)


def route(source):
    return f"1.1.1.1 via 10.0.0.1 dev eth0 src {source} uid 0 \\    cache "


def no_metadata():
    raise OSError("no metadata service")


class TestPublicAddress(unittest.TestCase):
    def test_an_address_on_the_interface_is_the_answer(self):
        self.assertEqual(facts.public_address(route("198.51.100.4"), no_metadata), "198.51.100.4")

    def test_behind_the_cloud_s_nat_the_metadata_service_answers(self):
        self.assertEqual(facts.public_address(route("10.131.0.4"), lambda: "203.0.113.7\n"), "203.0.113.7")

    def test_the_interface_wins_over_the_metadata_service(self):
        self.assertEqual(facts.public_address(route("198.51.100.4"), lambda: "203.0.113.7"), "198.51.100.4")

    def test_a_tunnel_or_private_answer_is_not_a_public_address(self):
        self.assertIsNone(facts.public_address(route("100.101.102.103"), lambda: "10.0.0.9"))

    def test_no_route_and_no_metadata_is_no_answer_rather_than_an_error(self):
        self.assertIsNone(facts.public_address("", no_metadata))

    def test_a_metadata_answer_that_is_not_an_address_is_no_answer(self):
        self.assertIsNone(facts.public_address(route("10.0.0.4"), lambda: "<html>not found</html>"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
