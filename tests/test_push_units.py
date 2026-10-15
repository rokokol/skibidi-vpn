"""The files the roles write to make the push and the daily check run.

The station is named once, by `backup_url`. Everything that pushes derives its
target from it, and these tests hold that: the same account as the backup, no
second copy of the address or the password, nothing installed on a node that
names no station, and the daily check on its own clock.
"""

from __future__ import annotations

import configparser
import re
import unittest
from pathlib import Path

import yaml
from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parent.parent
ROLES = ROOT / "roles"


def defaults(*roles: str) -> dict:
    values: dict = {}
    for role in roles:
        values.update(yaml.safe_load((ROLES / role / "defaults" / "main.yml").read_text()))
    # What Ansible supplies and no role default does
    values.update(
        firewall_tunnel_interface="tailscale0", inventory_hostname="node-a", group_names=[],
        backup_secrets={"node-a": {"rest_password": "rest-secret", "repository_password": "repo-secret"}},
    )
    env = environment()
    for _ in range(4):
        values = {
            key: env.from_string(value).render(values) if isinstance(value, str) else value
            for key, value in values.items()
        }
    return values


def environment() -> Environment:
    env = Environment(trim_blocks=True, undefined=StrictUndefined)
    env.filters["regex_replace"] = lambda text, pattern, replacement: re.sub(pattern, replacement, text)
    env.filters["quote"] = lambda text: text
    return env


def render(role: str, name: str, values: dict) -> str:
    return environment().from_string((ROLES / role / "templates" / name).read_text()).render(
        ansible_managed="rendered by the test", **values
    )


def unit(text: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    parser.read_string(text)
    return parser


def env_file(text: str) -> dict:
    """An EnvironmentFile= the way systemd reads it: a value may be quoted"""
    pairs = (line.split("=", 1) for line in text.splitlines() if line and not line.startswith("#"))
    return {key: value.strip('"') for key, value in pairs}


def minutes(span: str) -> int:
    """A systemd time span the roles write, such as 1min or 10min, in minutes"""
    return int(re.fullmatch(r"(\d+)min", span).group(1))


def tasks(role: str, name: str = "main.yml") -> list:
    return yaml.safe_load((ROLES / role / "tasks" / name).read_text())


class TestPushEnvironment(unittest.TestCase):
    def values(self, url="http://100.64.0.2:8000"):
        return dict(defaults("metrics", "backup", "checker"), backup_url=url)

    def pushed(self, url="http://100.64.0.2:8000"):
        return env_file(render("metrics", "push.env.j2", self.values(url)))

    def test_the_station_is_the_backup_station_on_the_gateways_port(self):
        self.assertEqual(self.pushed()["SKIBIDI_PUSH_BASE"], "http://100.64.0.2:9091")

    def test_the_scheme_and_the_host_follow_the_backup_url_whatever_its_shape(self):
        shapes = {
            "http://station.example.ts.net:8000/": "http://station.example.ts.net:9091",
            "https://backup.example.org": "https://backup.example.org:9091",
            "http://[fd7a:115c:a1e0::2]:8000": "http://[fd7a:115c:a1e0::2]:9091",
            "http://100.64.0.2": "http://100.64.0.2:9091",
        }
        for url, base in shapes.items():
            with self.subTest(url=url):
                self.assertEqual(self.pushed(url)["SKIBIDI_PUSH_BASE"], base)

    def test_the_account_is_the_backup_account(self):
        values = dict(self.values(), backup_user="node-a")
        self.assertEqual(env_file(render("metrics", "push.env.j2", values))["SKIBIDI_PUSH_USER"], "node-a")

    def test_the_password_stays_in_the_file_the_backup_wrote(self):
        found = self.pushed()["SKIBIDI_PUSH_PASSWORD_FILE"]
        written = [item["name"] for task in tasks("backup", "present.yml")
                   for item in task.get("loop", []) if isinstance(item, dict) and "name" in item]
        self.assertEqual(found, f"{self.values()['backup_config_dir']}/rest-password")
        self.assertIn(Path(found).name, written, "the backup role no longer writes that file")

    def test_the_station_is_checked_by_the_script_that_owns_the_rule(self):
        values = self.values()
        self.assertEqual(self.pushed()["SKIBIDI_PUSH_GUARD"], f"{values['backup_script']} target")

    def test_the_collector_reads_the_checks_record_where_the_check_writes_it(self):
        values = self.values()
        pushed = env_file(render("metrics", "push.env.j2", values))
        daily = env_file(render("checker", "skibidi-daily.env.j2", dict(values, metrics_host="100.64.0.1")))
        self.assertEqual(pushed["SKIBIDI_CHECK_RESULT"], values["checker_result_file"])
        for key in ("SKIBIDI_CHECK_RESULT", "SKIBIDI_CHECK_MAX_AGE_HOURS"):
            self.assertEqual(pushed[key], daily[key], "the push and the daily list judge the record differently")

    def test_the_default_port_is_the_gateways(self):
        self.assertEqual(self.values()["metrics_push_port"], 9091)

    def test_no_secret_is_in_the_file(self):
        values = dict(self.values(), backup_rest_password="s3cret-value-xyz")
        self.assertNotIn("s3cret-value-xyz", render("metrics", "push.env.j2", values))


class TestPushInstallation(unittest.TestCase):
    def test_the_file_is_written_only_for_a_node_that_names_a_station(self):
        main = tasks("metrics")
        write = [task for task in main if "ansible.builtin.template" in task
                 and task["ansible.builtin.template"]["src"] == "push.env.j2"]
        remove = [task for task in main if "ansible.builtin.file" in task
                  and task["ansible.builtin.file"].get("state") == "absent"
                  and "push" in task["ansible.builtin.file"]["path"]]
        self.assertEqual(len(write), 1)
        self.assertEqual(len(remove), 1, "a station taken away leaves its address on the node")
        self.assertIn("length > 0", write[0]["when"])
        self.assertIn("length == 0", remove[0]["when"])

    def test_the_library_reaches_every_node(self):
        copied = {item for task in tasks("metrics") if "ansible.builtin.copy" in task
                  for item in task.get("loop", [task["ansible.builtin.copy"]["src"]])}
        self.assertTrue({"skibidi_push.py", "skibidi_problems.py"} <= copied)

    def test_the_first_sample_does_not_push(self):
        # The password arrives with the backup role, after this one
        first = [task for task in tasks("metrics") if task.get("name") == "Take the first sample, now"]
        self.assertIn("--no-push", first[0]["ansible.builtin.command"]["argv"])

    def test_the_collector_unit_reads_the_file_if_there_is_one(self):
        values = defaults("metrics", "backup")
        text = render("metrics", "skibidi-metrics.service.j2", values)
        self.assertEqual(unit(text)["Service"]["EnvironmentFile"], f"-{values['metrics_push_env_file']}")
        # systemd reads a repeated Environment=; a parser keeps the last one
        self.assertIn(f"Environment=SKIBIDI_LIB={values['metrics_lib_dir']}\n", text)


class TestDailyCheckUnits(unittest.TestCase):
    def setUp(self):
        self.values = dict(defaults("metrics", "checker"), metrics_host="100.64.0.1")

    def test_it_runs_at_nine_in_moscow_every_day(self):
        timer = unit(render("checker", "skibidi-daily.timer.j2", self.values))["Timer"]
        self.assertEqual(timer["OnCalendar"], "*-*-* 09:00:00 Europe/Moscow")
        self.assertEqual(timer["Persistent"], "true")

    def test_the_hour_and_the_zone_are_settings(self):
        values = dict(self.values, checker_daily_hour=7, checker_daily_timezone="Europe/Berlin")
        timer = unit(render("checker", "skibidi-daily.timer.j2", values))["Timer"]
        self.assertEqual(timer["OnCalendar"], "*-*-* 07:00:00 Europe/Berlin")

    def test_a_listing_fails_the_unit_so_the_alert_path_mails_it(self):
        service = unit(render("checker", "skibidi-daily.service.j2", self.values))
        self.assertEqual(service["Unit"]["OnFailure"], "skibidi-alert@%N.service")
        self.assertEqual(service["Service"]["Type"], "oneshot")
        self.assertTrue(service["Service"]["ExecStart"].endswith("skibidi-daily"))

    def settings(self):
        return env_file(render("checker", "skibidi-daily.env.j2", self.values))

    def test_it_reads_the_record_the_check_writes_and_this_nodes_own_api(self):
        settings = self.settings()
        self.assertEqual(settings["SKIBIDI_CHECK_RESULT"], self.values["checker_result_file"])
        self.assertEqual(settings["SKIBIDI_API_URL"],
                         f"http://100.64.0.1:{self.values['metrics_api_port']}")

    def test_an_ipv6_address_is_bracketed_in_the_url(self):
        self.values["metrics_host"] = "fd7a:115c:a1e0::1"
        self.assertEqual(self.settings()["SKIBIDI_API_URL"],
                         f"http://[fd7a:115c:a1e0::1]:{self.values['metrics_api_port']}")

    def test_the_unit_and_a_run_by_hand_read_one_file(self):
        service = unit(render("checker", "skibidi-daily.service.j2", self.values))["Service"]
        self.assertEqual(service["EnvironmentFile"], self.values["checker_daily_env_file"])
        daily = [task for task in tasks("checker") if task.get("name") == "Run the daily check once, now"]
        self.assertIn(f"--property=EnvironmentFile={{{{ checker_daily_env_file }}}}",
                      daily[0]["ansible.builtin.command"]["argv"])

    def test_the_daily_run_of_a_deploy_leaves_no_failed_unit(self):
        # Exit 1 lists what is open and passes the deploy, and a transient unit
        # that exited 1 stays failed unless it is collected
        daily = [task for task in tasks("checker") if task.get("name") == "Run the daily check once, now"]
        self.assertIn("--collect", daily[0]["ansible.builtin.command"]["argv"])

    def test_a_deploy_pushes_what_its_first_check_found(self):
        # The metrics role pushes before the new check exists, so the station
        # would read a missing record until the next collection
        names = [task.get("name") for task in tasks("checker")]
        push = names.index("Tell the station what the check found, now")
        self.assertGreater(push, names.index("Run the checks once, now"))
        argv = tasks("checker")[push]["ansible.builtin.command"]["argv"]
        self.assertEqual(argv[-2:], ["/usr/local/sbin/skibidi-metrics", "push"])
        self.assertIn("--property=EnvironmentFile=-{{ metrics_push_env_file }}", argv)

    def test_the_settings_name_every_variable_the_script_requires(self):
        script = (ROLES / "checker" / "files" / "skibidi-daily.py").read_text()
        required = re.search(r"REQUIRED = \((.*?)\)", script).group(1)
        for name in re.findall(r'"(SKIBIDI_\w+)"', required):
            self.assertIn(name, self.settings())

    def test_a_result_is_stale_when_the_check_would_itself_be_reported_silent(self):
        silence = {timer["name"]: timer["max_silence_hours"]
                   for timer in self.values["checker_watched_timers"]}["skibidi-check.timer"]
        self.assertEqual(self.settings()["SKIBIDI_CHECK_MAX_AGE_HOURS"], str(silence))

    def test_the_daily_timer_is_watched_like_the_others(self):
        names = {timer["name"] for timer in self.values["checker_watched_timers"]}
        self.assertIn("skibidi-daily.timer", names)

    def test_the_check_script_and_the_unit_agree_on_the_record(self):
        template = (ROLES / "checker" / "templates" / "skibidi-check.j2").read_text()
        self.assertIn("{{ checker_result_file }}", template)


class TestTrafficUnits(unittest.TestCase):
    def setUp(self):
        self.values = defaults("metrics", "reporter")

    def test_the_master_writes_the_traffic_as_often_as_the_push_runs(self):
        # The dashboard's traffic is as fresh as the slower of the two
        timer = unit(render("reporter", "skibidi-traffic.timer.j2", self.values))["Timer"]
        self.assertLessEqual(minutes(timer["OnUnitActiveSec"]), minutes(self.values["metrics_push_interval"]))
        self.assertNotIn("RandomizedDelaySec", timer, "a scatter of a minute doubles a one-minute interval")

    def test_the_unit_takes_the_file_to_write_from_the_same_file_as_the_collector(self):
        values = self.values
        service = unit(render("reporter", "skibidi-traffic.service.j2", values))["Service"]
        self.assertEqual(service["EnvironmentFile"], f"-{values['metrics_push_env_file']}")
        self.assertTrue(service["ExecStart"].endswith("skibidi-report traffic"))

    def test_the_collector_and_the_reporter_agree_on_where_the_traffic_file_is(self):
        values = dict(defaults("metrics", "backup", "checker"), backup_url="http://100.64.0.2:8000")
        pushed = env_file(render("metrics", "push.env.j2", values))
        self.assertEqual(pushed["SKIBIDI_PUSH_TEXTFILE"], values["metrics_push_textfile"])

    def test_the_units_exist_only_on_a_node_that_names_a_station(self):
        main = tasks("reporter")
        installs = [task for task in main
                    if "ansible.builtin.template" in task
                    and "skibidi-traffic.timer" in str(task["ansible.builtin.template"]) + str(task.get("loop"))]
        removals = [task for task in main
                    if "ansible.builtin.file" in task
                    and task["ansible.builtin.file"].get("state") == "absent"
                    and "skibidi-traffic" in str(task["ansible.builtin.file"]) + str(task.get("loop"))]
        self.assertEqual(len(installs), 1)
        self.assertEqual(len(removals), 1)
        self.assertIn("length > 0", str(installs[0]["when"]))
        self.assertIn("length == 0", str(removals[0]["when"]))


class TestPushUnits(unittest.TestCase):
    """The push runs every minute on its own timer, apart from the sampling"""

    def setUp(self):
        self.values = defaults("metrics", "backup", "checker")

    def test_the_push_runs_every_minute_and_the_sampling_stays_slow(self):
        timer = unit(render("metrics", "skibidi-push.timer.j2", self.values))["Timer"]
        self.assertEqual(minutes(timer["OnUnitActiveSec"]), 1)
        self.assertGreater(minutes(self.values["metrics_interval"]), 1, "every sample is a row kept for months")

    def test_the_push_unit_pushes_with_the_push_settings(self):
        service = unit(render("metrics", "skibidi-push.service.j2", self.values))["Service"]
        self.assertEqual(service["ExecStart"], "/usr/local/sbin/skibidi-metrics push")
        self.assertEqual(service["EnvironmentFile"], f"-{self.values['metrics_push_env_file']}")

    def test_a_node_that_names_no_station_leaves_no_failed_unit(self):
        # The push says 3 for no station, and a failed unit is itself an alert
        service = unit(render("metrics", "skibidi-push.service.j2", self.values))["Service"]
        self.assertIn("3", service["SuccessExitStatus"].split())

    def test_the_push_timer_is_installed_enabled_and_watched(self):
        main = tasks("metrics")
        installs = [task for task in main if task.get("name") == "Install the units"]
        self.assertIn("skibidi-push.timer", installs[0]["loop"])
        enables = [task for task in main if task.get("name") == "Enable the timers"]
        self.assertIn("skibidi-push.timer", enables[0]["loop"])
        names = {timer["name"] for timer in self.values["checker_watched_timers"]}
        self.assertIn("skibidi-push.timer", names)
        self.assertIn("skibidi-traffic.timer", names)

    def test_the_master_names_its_own_inbounds_as_the_fleet_names_it(self):
        pushed = env_file(render("metrics", "push.env.j2", dict(self.values, backup_url="http://100.64.0.2:8000")))
        self.assertEqual(pushed["SKIBIDI_NODE_NAME"], "node-a")

    def test_the_push_is_told_where_the_attacks_are(self):
        pushed = env_file(render("metrics", "push.env.j2", dict(self.values, backup_url="http://100.64.0.2:8000")))
        self.assertEqual(pushed["SKIBIDI_FAIL2BAN_LOG"], self.values["metrics_fail2ban_log"])


class TestTheLetterIsGone(unittest.TestCase):
    """The weekly letter is deleted whole, and a deploy removes what it left"""

    def test_no_template_of_the_letter_or_its_snapshot_remains(self):
        names = {path.name for path in (ROLES / "reporter" / "templates").iterdir()}
        for gone in ("skibidi-report.service.j2", "skibidi-report.timer.j2",
                     "skibidi-snapshot.service.j2", "skibidi-snapshot.timer.j2"):
            self.assertNotIn(gone, names)

    def test_a_deploy_removes_the_units_and_the_history_an_earlier_one_left(self):
        text = (ROLES / "reporter" / "tasks" / "main.yml").read_text()
        for left in ("skibidi-report.timer", "skibidi-snapshot.timer", "skibidi-report.service",
                     "skibidi-snapshot.service", "snapshot-*.json"):
            self.assertIn(left, text)

    def test_the_old_timers_are_stopped_before_their_files_go(self):
        stops = [task for task in tasks("reporter") if "ansible.builtin.systemd_service" in task
                 and task["ansible.builtin.systemd_service"].get("state") == "stopped"]
        self.assertTrue(any("skibidi-report.timer" in str(task) for task in stops))
        self.assertTrue(any("skibidi-snapshot.timer" in str(task) for task in stops))

    def test_the_role_runs_on_the_master_without_an_alert_address(self):
        # Nothing here mails any more, so the alert address no longer decides
        site = (ROOT / "site.yml").read_text()
        self.assertNotIn("reporter_to", site)
        self.assertIn("'master' in group_names", site)

    def test_the_settings_of_a_letter_are_gone_from_the_defaults(self):
        text = (ROLES / "reporter" / "defaults" / "main.yml").read_text()
        for word in ("reporter_to", "reporter_hour", "reporter_weekday", "reporter_sendmail",
                     "reporter_timezone", "snapshot_minute"):
            self.assertNotIn(word, text)

    def test_the_theme_the_letter_wore_is_not_carried_by_the_reporter_any_more(self):
        self.assertNotIn("ddlc-mail", (ROLES / "reporter" / "tasks" / "main.yml").read_text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
