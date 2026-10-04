"""Tailscale SSH follows the node file, switched only after the play is done.

The switch takes port 22 on the tailnet address, which is where a play's own
SSH session may arrive, so it must be scheduled rather than run, and it must
run last. The role's tasks are applied here with stand-ins for tailscale and
systemd-run, which record what they were asked to do.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PLAY = """\
- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - ansible.builtin.import_role:
        name: tailscale
        tasks_from: ssh
"""


class TestTailscaleSsh(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        (self.dir / "play.yml").write_text(PLAY)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.calls = self.dir / "systemd-run.calls"
        stubs = {
            "tailscale": 'printf \'{"RunSSH": %s, "WantRunning": true}\\n\' "$STUB_RUN_SSH"',
            "systemd-run": f'printf "%s\\n" "$*" >> {self.calls}',
        }
        for name, body in stubs.items():
            (self.bin / name).write_text(f"#!/bin/sh\n{body}\n")
            (self.bin / name).chmod(0o755)

    def apply(self, running: bool, *extra: str) -> tuple[int, list[str]]:
        env = dict(os.environ, ANSIBLE_ROLES_PATH=str(ROOT / "roles"),
                   STUB_RUN_SSH="true" if running else "false",
                   PATH=f"{self.bin}:{os.environ['PATH']}")
        env.pop("ANSIBLE_CONFIG", None)
        done = subprocess.run(
            ["ansible-playbook", "-i", "localhost,", *extra, str(self.dir / "play.yml")],
            cwd=self.dir, env=env, capture_output=True, text=True,
        )
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        changed = int(re.search(r"changed=(\d+)", done.stdout).group(1))
        calls = self.calls.read_text().splitlines() if self.calls.exists() else []
        return changed, calls

    def test_a_node_that_opts_in_is_switched_on_later(self):
        changed, calls = self.apply(False, "-e", '{"tailscale_ssh": true}')
        self.assertEqual(changed, 1)
        self.assertEqual(len(calls), 1)
        self.assertIn("--on-active=10", calls[0])
        self.assertIn("/usr/bin/tailscale set --ssh=true", calls[0])

    def test_a_node_already_switched_is_left_alone(self):
        self.assertEqual(self.apply(True, "-e", '{"tailscale_ssh": true}'), (0, []))

    def test_the_default_switches_a_stray_setting_off(self):
        changed, calls = self.apply(True)
        self.assertEqual(changed, 1)
        self.assertIn("--ssh=false", calls[0])

    def test_the_default_leaves_a_node_without_it_alone(self):
        self.assertEqual(self.apply(False), (0, []))

    def test_the_node_file_switch_reaches_the_role_as_a_boolean(self):
        sys.path.insert(0, str(ROOT / "inventory"))
        try:
            import nodes
        finally:
            sys.path.pop(0)
        node = self.dir / "nodes"
        node.mkdir()
        (node / "n.toml").write_text('ansible_host = "198.51.100.1"\ntailscale_ssh = true\n')
        (node / "n.toml").chmod(0o600)
        self.assertIs(nodes.build(node)["_meta"]["hostvars"]["n"]["tailscale_ssh"], True)

    def test_the_switch_is_the_last_play_and_nothing_runs_after_it(self):
        for playbook in ("site.yml", "molecule/default/converge.yml"):
            with self.subTest(playbook=playbook):
                plays = yaml.safe_load((ROOT / playbook).read_text())
                last = plays[-1]
                self.assertNotIn("roles", last)
                self.assertEqual(
                    [task.get("ansible.builtin.include_role") for task in last["tasks"]],
                    [{"name": "tailscale", "tasks_from": "ssh"}],
                )

    def test_the_join_does_not_switch_it_mid_play(self):
        main = (ROOT / "roles" / "tailscale" / "tasks" / "main.yml").read_text()
        self.assertNotIn("tailscale set", main)
        self.assertNotIn("ssh.yml", main)


if __name__ == "__main__":
    unittest.main()
