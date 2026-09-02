"""The one door the master's key opens on a node.

authorized_keys forces this entry point, so the only thing standing between a
metrics key and a root shell is the shape this module matches. That makes it
the most security-sensitive line in the repository, and it had no test: it was
checked once by hand, which stops being true the moment the pattern is edited.

The export itself is replaced here. What is under test is the decision to run
it at all.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "roles" / "metrics" / "files" / "skibidi-metrics.py"


def load():
    spec = importlib.util.spec_from_file_location("skibidi_metrics", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["skibidi_metrics"] = module
    spec.loader.exec_module(module)
    return module


class TestSshGuard(unittest.TestCase):
    def setUp(self):
        self.module = load()
        self.exported: list[tuple[int, int]] = []

        def fake_export(since, until):
            self.exported.append((since, until))
            return 0

        self.module.export = fake_export

    def run_guard(self, command: str) -> int:
        import os

        os.environ["SSH_ORIGINAL_COMMAND"] = command
        try:
            return self.module.ssh_guard()
        finally:
            os.environ.pop("SSH_ORIGINAL_COMMAND", None)

    def test_the_one_permitted_shape_is_allowed(self):
        self.assertEqual(self.run_guard("skibidi-metrics export --since 10 --until 20"), 0)
        self.assertEqual(self.exported, [(10, 20)])

    def test_a_shell_is_refused(self):
        for command in ("bash", "sh -c id", "/bin/bash -i"):
            with self.subTest(command=command):
                self.assertNotEqual(self.run_guard(command), 0)
        self.assertEqual(self.exported, [], "a shell reached the export")

    def test_an_empty_command_is_refused(self):
        # An interactive login arrives with no original command at all
        self.assertNotEqual(self.run_guard(""), 0)

    def test_the_other_subcommand_is_refused(self):
        # collect writes to the store; this key may only read from it
        self.assertNotEqual(self.run_guard("skibidi-metrics collect"), 0)

    def test_a_second_command_cannot_ride_along(self):
        for suffix in ("; id", "&& id", "| id", "$(id)", "`id`", "\nid"):
            with self.subTest(suffix=suffix):
                command = f"skibidi-metrics export --since 1 --until 2{suffix}"
                self.assertNotEqual(self.run_guard(command), 0)
        self.assertEqual(self.exported, [], "a smuggled command reached the export")

    def test_arguments_must_be_numbers(self):
        for command in (
            "skibidi-metrics export --since abc --until 2",
            "skibidi-metrics export --since -1 --until 2",
            "skibidi-metrics export --since 1 --until /etc/shadow",
        ):
            with self.subTest(command=command):
                self.assertNotEqual(self.run_guard(command), 0)

    def test_extra_arguments_are_refused(self):
        self.assertNotEqual(
            self.run_guard("skibidi-metrics export --since 1 --until 2 --output /tmp/x"), 0
        )

    def test_a_different_program_is_refused(self):
        self.assertNotEqual(self.run_guard("cat export --since 1 --until 2"), 0)

    def test_absurdly_long_numbers_are_refused(self):
        # The shape bounds the digits, so a caller cannot make the node chew on
        # an arbitrarily large integer
        long_number = "9" * 40
        self.assertNotEqual(
            self.run_guard(f"skibidi-metrics export --since {long_number} --until 2"), 0
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
