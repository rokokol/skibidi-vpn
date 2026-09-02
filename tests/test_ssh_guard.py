"""The one door the master's key opens on a node.

authorized_keys forces this entry point, so the only thing standing between a
metrics key and a root shell is the shape this module matches. That makes it
the most security-sensitive line in the repository, and it had no test: it was
checked once by hand, which stops being true the moment the pattern is edited.

The export itself is replaced here. What is under test is the decision to run
it at all.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import sqlite3
import sys
import tempfile
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


class TestReadOnlyExport(unittest.TestCase):
    """What the export may do once the guard lets it run.

    The guard decides whether export runs at all; these hold what it can do
    when it does. The export serves an unprivileged account, and a store
    opened writable "just in case" is the difference between a leaked key
    reading metrics and a leaked key corrupting them.
    """

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "metrics.db"
        os.environ["SKIBIDI_METRICS_DB"] = str(self.db)
        self.addCleanup(os.environ.pop, "SKIBIDI_METRICS_DB", None)
        self.module = load()

    def write_one_sample(self):
        with self.module.connect() as connection:
            connection.execute(
                "INSERT INTO samples (ts_us, metric, detail, value) VALUES (1, 'load1', '', 0.5)"
            )
        connection.close()

    def test_export_does_not_create_a_missing_store(self):
        # A read-write open would conjure an empty store here, turning "the
        # collector never ran" into a healthy-looking week of zeros
        with self.assertRaises(sqlite3.OperationalError):
            self.module.export(0, 10**16)
        self.assertFalse(self.db.exists(), "the export created the store it failed to read")

    def test_the_readonly_connection_refuses_writes(self):
        self.write_one_sample()
        readonly = self.module.connect_readonly()
        self.addCleanup(readonly.close)
        with self.assertRaises(sqlite3.OperationalError):
            readonly.execute(
                "INSERT INTO samples (ts_us, metric, detail, value) VALUES (2, 'load1', '', 1.0)"
            )

    def test_export_still_reads_what_the_collector_wrote(self):
        # Read-only must not mean broken: the same call the guard permits has
        # to keep answering, or the narrowing quietly killed the report
        self.write_one_sample()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(self.module.export(0, 10**16), 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(len(payload["samples"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
