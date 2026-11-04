"""Where the panel credential comes from, who may read it, and what a node does
without one. What the collector does with it is held in test_panel_metrics.py.
"""

from __future__ import annotations

import json
import re
import unittest

import yaml

from test_push_units import ROLES, defaults, env_file, environment, render, tasks

PANEL_TASKS = "panel.yml"
RAW_DEFAULTS = yaml.safe_load((ROLES / "metrics" / "defaults" / "main.yml").read_text())


def expression(name: str, **values) -> str:
    """A default rendered from the raw file, since the shared helper renders
    every value once already and these are about what the expression reads"""
    context = dict(defaults("metrics"), **values)
    return environment().from_string(RAW_DEFAULTS[name]).render(context)


def panel_tasks() -> list:
    return tasks("metrics", PANEL_TASKS)


def by_module(module: str) -> list:
    return [task for task in panel_tasks() if module in task]


class TestPanelDefaults(unittest.TestCase):
    def test_collection_is_off_until_a_node_asks_for_it(self):
        self.assertIs(defaults("metrics")["metrics_panel_enabled"], False)

    def test_the_token_comes_from_the_vault_entry_of_this_node(self):
        found = expression("metrics_panel_token",
                           metrics_panel_secrets={"node-a": {"token": "from-the-vault"}})
        self.assertEqual(found, "from-the-vault")

    def test_another_nodes_entry_is_not_taken_for_this_one(self):
        found = expression("metrics_panel_token",
                           metrics_panel_secrets={"node-b": {"token": "not-mine"}})
        self.assertEqual(found, "")

    def test_a_node_without_an_entry_resolves_to_no_token_rather_than_failing(self):
        self.assertEqual(expression("metrics_panel_token"), "")

    def test_the_url_follows_the_panel_the_roles_placed(self):
        self.assertEqual(expression("metrics_panel_url", xui_listen_ip="100.72.0.4",
                                     xui_panel_port=16099, xui_base_path="/randomBasePath/",
                                     metrics_panel_tls=False),
                         "http://100.72.0.4:16099/randomBasePath/")

    def test_a_node_whose_panel_serves_tls_reaches_it_over_tls(self):
        self.assertEqual(expression("metrics_panel_url", xui_listen_ip="100.72.0.4",
                                     xui_panel_port=16099, xui_base_path="/randomBasePath/",
                                     metrics_panel_tls=True),
                         "https://100.72.0.4:16099/randomBasePath/")


class TestPanelTasks(unittest.TestCase):
    def test_a_node_that_asks_for_collection_without_a_token_fails_before_anything_is_written(self):
        guards = by_module("ansible.builtin.assert")
        self.assertEqual(len(guards), 1)
        guard = guards[0]
        self.assertIn("metrics_panel_token | length > 0", guard["ansible.builtin.assert"]["that"])
        self.assertIn("metrics_panel_secrets", guard["ansible.builtin.assert"]["fail_msg"])
        self.assertEqual(guard["when"], "metrics_panel_enabled")
        self.assertIs(guard.get("no_log"), True, "a failure message must not echo what it guards")
        self.assertLess(panel_tasks().index(guard), panel_tasks().index(by_module("ansible.builtin.template")[0]))

    def test_the_token_reaches_the_node_in_a_root_only_file(self):
        [template] = by_module("ansible.builtin.template")
        self.assertEqual(template["ansible.builtin.template"]["src"], "panel-metrics.json.j2")
        self.assertEqual(template["ansible.builtin.template"]["dest"], "{{ metrics_panel_config }}")
        self.assertEqual(template["ansible.builtin.template"]["mode"], "0600")
        self.assertEqual(template["ansible.builtin.template"]["owner"], "root")
        self.assertIs(template["no_log"], True, "the token would print on a failure")

    def test_the_file_is_taken_away_from_a_node_that_stopped_collecting(self):
        removals = [task for task in by_module("ansible.builtin.file")
                    if task["ansible.builtin.file"].get("state") == "absent"]
        self.assertEqual(len(removals), 1)
        self.assertEqual(removals[0]["ansible.builtin.file"]["path"], "{{ metrics_panel_config }}")
        self.assertEqual(removals[0]["when"], "not metrics_panel_enabled")

    def test_the_credential_is_proved_against_the_panel_before_a_deploy_is_called_done(self):
        probes = [task for task in by_module("ansible.builtin.command")
                  if "skibidi_panel" in str(task["ansible.builtin.command"]["argv"])]
        self.assertEqual(len(probes), 1)
        self.assertEqual(probes[0]["when"], "metrics_panel_enabled")
        self.assertIs(probes[0]["changed_when"], False)

    def test_the_pin_is_read_from_the_panel_it_pins_and_only_over_tls(self):
        [pin] = [task for task in by_module("ansible.builtin.command")
                 if "getpeercert" in str(task["ansible.builtin.command"]["argv"])]
        argv = " ".join(str(item) for item in pin["ansible.builtin.command"]["argv"])
        self.assertIn("xui_listen_ip", argv)
        self.assertIn("xui_panel_port", argv)
        self.assertIn("metrics_panel_tls", pin["when"])
        self.assertIn("metrics_panel_enabled", pin["when"])
        self.assertIs(pin["changed_when"], False)

    def test_the_role_reads_no_default_of_another_role(self):
        # A role's defaults load only in a play that lists it, and certs is listed
        # behind a certificate. Anything borrowed here fails a play that runs this
        # role alone, which is how a single change is deployed
        borrowed = sorted({
            word
            for path in ROLES.joinpath("metrics").rglob("*")
            if path.is_file()
            for word in re.findall(r"\b(certs_[a-z_]+)", path.read_text(errors="replace"))
        })
        self.assertEqual(borrowed, [])


class TestPanelFiles(unittest.TestCase):
    def values(self, **overrides):
        base = dict(defaults("metrics", "backup", "checker"), backup_url="http://100.64.0.2:8000",
                    metrics_panel_enabled=True,
                    metrics_panel_url="http://100.72.0.4:16099/randomBasePath/",
                    metrics_panel_token="replace-me")
        return dict(base, **overrides)

    def config(self, values):
        return json.loads(render("metrics", "panel-metrics.json.j2", values))

    def test_the_file_carries_the_url_and_the_token(self):
        values = self.values()
        rendered = render("metrics", "panel-metrics.json.j2", values)
        self.assertEqual(set(json.loads(rendered)), {"url", "token", "pin_sha256"})
        self.assertEqual(self.config(values)["token"], "replace-me")
        self.assertTrue(rendered.endswith("\n"), "a file without a final newline reads as truncated")

    def test_a_tls_panel_carries_the_pin_of_the_certificate_it_presents(self):
        values = self.values(certs_domain="example.org")
        values["metrics_panel_pin"] = {"stdout": "ab" * 32}
        self.assertEqual(self.config(values)["pin_sha256"], "ab" * 32)

    def test_a_plain_panel_carries_an_empty_pin_rather_than_a_wrong_one(self):
        values = self.values()
        values["metrics_panel_pin"] = {"skipped": True}
        self.assertEqual(self.config(values)["pin_sha256"], "")

    def test_the_push_environment_holds_the_path_and_never_the_token(self):
        text = render("metrics", "push.env.j2", self.values())
        self.assertEqual(env_file(text)["SKIBIDI_PANEL_CONFIG"], self.values()["metrics_panel_config"])
        self.assertNotIn("replace-me", text)

    def test_a_node_that_does_not_collect_has_no_panel_variable(self):
        self.assertNotIn("SKIBIDI_PANEL_CONFIG", env_file(render("metrics", "push.env.j2",
                                                                self.values(metrics_panel_enabled=False))))


if __name__ == "__main__":
    unittest.main()
