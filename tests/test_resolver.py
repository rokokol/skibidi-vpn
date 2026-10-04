"""The resolver a node ends up with, proved by running the role's own tasks.

Xray on a node resolves through the system resolver, so /etc/resolv.conf decides
which third party sees every name a client asks for. The tasks are applied here
to a scratch path, with the real role defaults, against the two shapes the
fleet has: a plain file that somebody wrote once, and the symlink into
systemd-resolved's runtime directory. A write that follows that symlink would
put the servers into a file the next boot throws away, so the symlink case
is the one that matters.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLAY = """\
- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - ansible.builtin.import_role:
        name: common
        tasks_from: dns
"""
# JSON, so the value is a boolean as a node file's TOML false is; key=value
# would hand the role the string "false"
SWITCH_OFF = '{"common_manage_resolver": false}'
GOOGLE = re.compile(r"8\.8\.8\.8|8\.8\.4\.4|2001:4860", re.IGNORECASE)


def nameservers(path: Path) -> list[str]:
    return [
        line.split()[1]
        for line in path.read_text().splitlines()
        if line.startswith("nameserver ")
    ]


class TestResolver(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.target = self.dir / "resolv.conf"
        (self.dir / "play.yml").write_text(PLAY)

    def apply(self, *extra: str) -> int:
        """Run the tasks once and return how many of them changed something."""
        env = dict(os.environ, ANSIBLE_ROLES_PATH=str(ROOT / "roles"))
        env.pop("ANSIBLE_CONFIG", None)
        done = subprocess.run(
            [
                "ansible-playbook",
                "-i", "localhost,",
                "-e", f"common_resolv_conf={self.target}",
                *extra,
                str(self.dir / "play.yml"),
            ],
            cwd=self.dir,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        found = re.search(r"changed=(\d+)", done.stdout)
        self.assertIsNotNone(found, done.stdout)
        return int(found.group(1))

    def test_quad9_first_and_cloudflare_the_only_fallback(self):
        self.target.write_text("nameserver 192.0.2.1\n")
        self.apply()
        self.assertEqual(nameservers(self.target), ["9.9.9.9", "1.1.1.1"])

    def test_a_symlink_is_replaced_not_written_through(self):
        runtime = self.dir / "stub-resolv.conf"
        runtime.write_text("nameserver 127.0.0.53\n")
        self.target.symlink_to(runtime)
        self.apply()
        self.assertFalse(self.target.is_symlink(), "the link survived")
        self.assertEqual(nameservers(self.target), ["9.9.9.9", "1.1.1.1"])
        self.assertEqual(runtime.read_text(), "nameserver 127.0.0.53\n")

    def test_a_second_run_changes_nothing(self):
        self.target.write_text("nameserver 192.0.2.1\n")
        self.apply()
        self.assertEqual(self.apply(), 0)

    def test_the_switch_off_leaves_a_symlink_and_its_target_alone(self):
        runtime = self.dir / "stub-resolv.conf"
        runtime.write_text("nameserver 127.0.0.53\n")
        self.target.symlink_to(runtime)
        self.assertEqual(self.apply("-e", SWITCH_OFF), 0)
        self.assertTrue(self.target.is_symlink(), "the link was replaced")
        self.assertEqual(self.target.resolve(), runtime.resolve())
        self.assertEqual(runtime.read_text(), "nameserver 127.0.0.53\n")

    def test_the_switch_off_leaves_a_plain_file_alone(self):
        self.target.write_text("nameserver 192.0.2.1\n")
        self.assertEqual(self.apply("-e", SWITCH_OFF), 0)
        self.assertEqual(self.target.read_text(), "nameserver 192.0.2.1\n")

    def test_a_node_file_switch_reaches_the_role(self):
        # The inventory passes every key that is not secret-shaped and not an
        # ansible_ key, so the switch needs no entry of its own
        sys.path.insert(0, str(ROOT / "inventory"))
        try:
            import nodes
        finally:
            sys.path.pop(0)
        node = self.dir / "nodes"
        node.mkdir()
        (node / "n.toml").write_text(
            'ansible_host = "198.51.100.1"\ncommon_manage_resolver = false\n'
        )
        (node / "n.toml").chmod(0o600)
        hostvars = nodes.build(node)["_meta"]["hostvars"]["n"]
        self.assertIs(hostvars["common_manage_resolver"], False)

    def test_no_role_scenario_or_example_names_google(self):
        hits = []
        for top in ("roles", "molecule", "inventory.example"):
            for path in (ROOT / top).rglob("*"):
                if path.is_file() and path.suffix != ".gpg":
                    if GOOGLE.search(path.read_text(errors="replace")):
                        hits.append(str(path.relative_to(ROOT)))
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
