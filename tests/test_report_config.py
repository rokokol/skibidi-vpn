"""The report's configuration, held to what the template promises.

The reporter reads the panel's database, and that is all its configuration
says. It does not list the fleet: the letter that pulled every node is gone,
and a node list kept here would be a second copy of the registry that nothing
reads. It names no mail path and no state either. It holds no credential,
so the panel stays a file permission and the station's password stays in the
backup role's root-only file.
"""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "roles" / "reporter" / "templates" / "report.toml.j2"


def render() -> dict:
    env = Environment(trim_blocks=True, undefined=StrictUndefined)
    text = env.from_string(TEMPLATE.read_text()).render(
        ansible_managed="rendered by the test",
        reporter_panel_db="/etc/x-ui/x-ui.db",
        metrics_push_env_file="/etc/skibidi/push.env",
    )
    return tomllib.loads(text)


class TestReportConfig(unittest.TestCase):
    def test_the_panel_is_a_database_and_no_credential(self):
        # A url or a token here would mean the API is back, and with it the
        # rotation that knocks out every other holder of the CLI's token
        self.assertEqual(render()["panel"], {"db": "/etc/x-ui/x-ui.db"})

    def test_the_report_no_longer_lists_the_fleet(self):
        config = render()
        self.assertNotIn("nodes", config)
        self.assertNotIn("metrics", config)
        self.assertNotIn("[[nodes]]", TEMPLATE.read_text())

    def test_it_holds_nothing_but_the_panel(self):
        self.assertEqual(list(render()), ["panel"])

    def test_no_password_is_written_here(self):
        self.assertNotIn("password", TEMPLATE.read_text().lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
