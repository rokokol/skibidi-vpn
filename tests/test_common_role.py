"""What the common role puts on every node beneath the services."""

from __future__ import annotations

import unittest

from test_push_units import tasks


class TestLoginSessions(unittest.TestCase):
    def test_every_login_is_registered_with_systemd(self):
        # Without pam_systemd every SSH login leaves user@0.service failed, and
        # a failed unit is what the checks and the station look for
        installs = [task["ansible.builtin.apt"] for task in tasks("common") if "ansible.builtin.apt" in task]
        names = [name for task in installs for name in ([task["name"]] if isinstance(task["name"], str) else task["name"])]
        self.assertIn("libpam-systemd", names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
