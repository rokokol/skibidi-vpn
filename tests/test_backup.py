"""The backup role's script, units and checker section, run on a laptop.

The script is rendered from the role's template and run for real against
SQLite stores made here. Most cases use a stand-in for restic that records what
it was asked and with what environment: where the secrets travel, when the
repository is created, what is staged, and which stations are refused. The last
class runs the real restic against a real rest-server, append-only with private
repositories, the way the station runs: the push arrives, restores whole, and
the node cannot delete it. The VM test asks the same of the deployed units.
"""

from __future__ import annotations

import base64
import configparser
import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import sqlite3
import stat
import subprocess
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path

import yaml
from jinja2 import Environment, StrictUndefined, meta

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "roles" / "backup"
CHECKER = ROOT / "roles" / "checker" / "templates" / "skibidi-check.j2"

# Characters a shell, a URL or an env file would each mangle in its own way
REST_PASSWORD = "a:b@c/d%e#f?g&h \"q' $x\\y"
REPOSITORY_PASSWORD = "r$e'p\"o pass"


def environment() -> Environment:
    env = Environment(trim_blocks=True, undefined=StrictUndefined)
    env.filters["quote"] = shlex.quote
    env.filters["regex_replace"] = lambda value, pattern, replacement: re.sub(pattern, replacement, value)
    return env


def defaults(**context) -> dict:
    """The role's defaults, resolved the way Ansible would for one node."""
    values = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    scope = {
        "inventory_hostname": "node-1",
        "group_names": [],
        "metrics_tunnel_ranges": ["100.64.0.0/10", "fd7a:115c:a1e0::/48"],
        "backup_secrets": {"node-1": {"rest_password": REST_PASSWORD,
                                      "repository_password": REPOSITORY_PASSWORD}},
        **context,
    }
    values.update({key: value for key, value in context.items() if key in values})
    # Each default is rendered once every default it names is resolved, the
    # order Ansible's lazy lookup ends up taking
    resolved: dict = {}
    while values:
        ready = [key for key, value in values.items() if not names(value) & values.keys()]
        if not ready:
            raise ValueError(f"defaults name each other in a circle: {sorted(values)}")
        for key in ready:
            resolved[key] = render_value(values.pop(key), {**scope, **resolved})
    return {**scope, **resolved}


def names(value) -> set:
    if isinstance(value, str):
        return meta.find_undeclared_variables(environment().parse(value))
    if isinstance(value, list):
        return set().union(*(names(item) for item in value))
    return set()


def render_value(value, scope):
    if isinstance(value, str):
        rendered = environment().from_string(value).render(scope)
        # A default that renders to a list or a boolean arrives as its repr;
        # Ansible hands such a value back in its native type
        if rendered.startswith("[") and rendered.endswith("]"):
            return yaml.safe_load(rendered)
        return {"True": True, "False": False}.get(rendered, rendered)
    if isinstance(value, list):
        return [render_value(item, scope) for item in value]
    return value


def render(name: str, values: dict) -> str:
    return environment().from_string((ROLE / "templates" / name).read_text()).render(
        ansible_managed="rendered by the test", **values
    )


TUNNEL_URL = "http://100.64.0.2:8000"


def http(host: str) -> str:
    """A plain HTTP station URL on the receiver's port, brackets for IPv6."""
    return f"http://[{host}]:8000" if ":" in host else f"http://{host}:8000"


def write_script(directory: Path, url: str, **paths) -> Path:
    """The script rendered for one station, with every path under directory."""
    values = {
        **defaults(backup_url=url),
        "backup_restic_path": str(directory / "bin" / "restic"),
        "backup_config_dir": str(directory / "config"),
        "backup_state_dir": str(directory / "state"),
        "backup_cache_dir": str(directory / "cache"),
        "backup_databases": [],
        "backup_directories": [],
        "backup_excludes": [],
        **paths,
    }
    path = directory / "skibidi-backup"
    path.write_text(render("skibidi-backup.j2", values))
    path.chmod(0o700)
    return path


def unit(name: str, values: dict) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    parser.read_string(render(name, values))
    return parser


class TestDefaults(unittest.TestCase):
    def test_the_channel_is_off_unless_a_node_sets_a_url(self):
        self.assertEqual(defaults()["backup_url"], "")

    def test_the_repository_is_the_node_account_under_the_station_url(self):
        for url in (TUNNEL_URL, TUNNEL_URL + "/", TUNNEL_URL + "//"):
            with self.subTest(url=url):
                self.assertEqual(defaults(backup_url=url)["backup_repository"],
                                 "rest:http://100.64.0.2:8000/node-1/")

    def test_the_secrets_come_from_the_vault_entry_of_this_node(self):
        values = defaults(backup_url=TUNNEL_URL)
        self.assertEqual(values["backup_rest_password"], REST_PASSWORD)
        self.assertEqual(values["backup_repository_password"], REPOSITORY_PASSWORD)

    def test_the_report_state_is_pushed_from_the_master_alone(self):
        self.assertEqual(defaults()["backup_directories"], [])
        self.assertEqual(defaults(group_names=["master"])["backup_directories"],
                         ["/var/lib/skibidi-report"])

    def test_the_panel_database_and_the_metric_store_are_staged_everywhere(self):
        self.assertEqual(defaults()["backup_databases"],
                         ["/etc/x-ui/x-ui.db", "/var/lib/skibidi-metrics/metrics.db"])


class TestUnits(unittest.TestCase):
    def setUp(self):
        self.values = defaults(backup_url=TUNNEL_URL)
        self.service = unit("skibidi-backup.service.j2", self.values)
        self.timer = unit("skibidi-backup.timer.j2", self.values)

    def test_a_failed_push_raises_the_fleet_alert(self):
        self.assertEqual(self.service["Unit"]["OnFailure"], "skibidi-alert@%N.service")

    def test_the_service_runs_the_script_and_nothing_else(self):
        self.assertEqual(self.service["Service"]["ExecStart"], "/usr/local/sbin/skibidi-backup run")
        self.assertEqual(self.service["Service"]["Type"], "oneshot")

    def test_the_service_carries_no_environment(self):
        # systemctl show prints both to any local account
        for key in ("Environment", "EnvironmentFile", "LoadCredential", "SetCredential"):
            self.assertNotIn(key, self.service["Service"])

    def test_the_timer_is_daily_and_catches_up(self):
        self.assertEqual(self.timer["Timer"]["OnCalendar"], "daily")
        self.assertEqual(self.timer["Timer"]["Persistent"], "true")
        self.assertEqual(self.timer["Install"]["WantedBy"], "timers.target")

    def test_no_secret_reaches_a_rendered_file(self):
        for name in ("skibidi-backup.j2", "skibidi-backup.service.j2", "skibidi-backup.timer.j2"):
            with self.subTest(name=name):
                text = render(name, self.values)
                self.assertNotIn(REST_PASSWORD, text)
                self.assertNotIn(REPOSITORY_PASSWORD, text)


# Records each call as one line of arguments and the restic environment it saw,
# and answers `cat config` with STUB_CAT_RC
RESTIC_STUB = """#!/usr/bin/env python3
import json, os, sys
with open(os.environ["STUB_LOG"], "a") as log:
    log.write(json.dumps({"argv": sys.argv[1:],
                          "env": {k: v for k, v in os.environ.items() if k.startswith("RESTIC_")}}) + "\\n")
if sys.argv[1:3] == ["cat", "config"]:
    rc = int(os.environ.get("STUB_CAT_RC", "0"))
    if rc:
        print(f"Fatal: stub refuses with {rc}", file=sys.stderr)
    sys.exit(rc)
"""


class TestScript(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.log = self.dir / "restic.log"

        (self.dir / "bin").mkdir()
        restic = self.dir / "bin" / "restic"
        restic.write_text(RESTIC_STUB)
        restic.chmod(0o755)

        config = self.dir / "config"
        config.mkdir(mode=0o700)
        (config / "rest-password").write_text(REST_PASSWORD)
        (config / "repository-password").write_text(REPOSITORY_PASSWORD)

        self.panel = self.dir / "etc" / "x-ui" / "x-ui.db"
        self.panel.parent.mkdir(parents=True)
        # WAL, like the panel's own: a file copy without the log would lose rows
        # WAL and held open with checkpoints off, the way the running panel
        # holds it: the row lives in the log alone, and a copy of the main file
        # would not have it
        self.writer = sqlite3.connect(self.panel)
        self.addCleanup(self.writer.close)
        self.writer.execute("pragma journal_mode=wal")
        self.writer.execute("pragma wal_autocheckpoint=0")
        self.writer.execute("create table settings (key text, value text)")
        self.writer.execute("insert into settings values ('webPort', '2053')")
        self.writer.commit()
        self.metrics = self.dir / "metrics.db"
        with closing(sqlite3.connect(self.metrics)) as db:
            db.execute("create table samples (value real)")
            db.execute("insert into samples values (1)")
            db.commit()
        self.report = self.dir / "report"
        (self.report / "mpl").mkdir(parents=True)
        (self.report / "snapshot-2026-10-05.json").write_text("{}")

    def script(self, url=TUNNEL_URL) -> Path:
        return write_script(
            self.dir, url,
            backup_databases=[str(self.panel), str(self.metrics)],
            backup_directories=[str(self.report)],
            backup_excludes=[str(self.report / "mpl")],
        )

    def run_script(self, *args, url=TUNNEL_URL, cat_rc=0):
        env = {**os.environ, "STUB_LOG": str(self.log), "STUB_CAT_RC": str(cat_rc)}
        return subprocess.run([str(self.script(url)), *args],
                              capture_output=True, text=True, env=env, check=False)

    def calls(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_the_rendered_script_passes_shellcheck(self):
        if shutil.which("shellcheck") is None:
            self.fail("shellcheck is not on PATH; run the suite inside `nix develop .#ci`")
        result = subprocess.run(["shellcheck", str(self.script())], capture_output=True, text=True,
                                check=False)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_a_first_run_creates_the_repository_then_pushes(self):
        result = self.run_script("run", cat_rc=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("pushed a snapshot", result.stdout)
        verbs = [call["argv"][0] for call in self.calls()]
        self.assertEqual(verbs, ["cat", "init", "backup"])

    def test_an_existing_repository_is_not_created_again(self):
        result = self.run_script("run", cat_rc=0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call["argv"][0] for call in self.calls()], ["cat", "backup"])

    def test_a_repository_it_cannot_open_stops_the_run(self):
        # 12 is a wrong repository password: a second init would hide it
        for rc in (1, 12):
            with self.subTest(rc=rc):
                self.log.unlink(missing_ok=True)
                result = self.run_script("run", cat_rc=rc)
                self.assertEqual(result.returncode, 1)
                self.assertIn(f"restic exit {rc}", result.stderr)
                self.assertEqual([call["argv"][0] for call in self.calls()], ["cat"])

    def test_the_secrets_travel_in_the_environment_and_files_alone(self):
        self.run_script("run")
        for call in self.calls():
            self.assertNotIn(REST_PASSWORD, " ".join(call["argv"]))
            self.assertNotIn(REPOSITORY_PASSWORD, " ".join(call["argv"]))
            env = call["env"]
            self.assertEqual(env["RESTIC_REST_PASSWORD"], REST_PASSWORD)
            self.assertEqual(env["RESTIC_REST_USERNAME"], "node-1")
            self.assertEqual(env["RESTIC_PASSWORD_FILE"], str(self.dir / "config" / "repository-password"))
            self.assertEqual(env["RESTIC_REPOSITORY"], "rest:http://100.64.0.2:8000/node-1/")

    def test_the_push_names_the_staging_directory_and_the_report_state(self):
        self.run_script("run")
        backup = self.calls()[-1]["argv"]
        self.assertEqual(backup[backup.index("--host") + 1], "node-1")
        self.assertEqual(backup[backup.index("--exclude") + 1], str(self.report / "mpl"))
        self.assertEqual(backup[-2:], [str(self.dir / "state" / "staging"), str(self.report)])

    def test_each_store_is_staged_whole_and_for_root_alone(self):
        result = self.run_script("run")
        self.assertEqual(result.returncode, 0, result.stderr)
        staging = self.dir / "state" / "staging"
        for source, table in ((self.panel, "settings"), (self.metrics, "samples")):
            with self.subTest(source=source.name):
                copy = Path(f"{staging}{source}")
                with closing(sqlite3.connect(copy)) as db:
                    self.assertEqual(db.execute("pragma integrity_check").fetchone(), ("ok",))
                    self.assertEqual(db.execute(f"select count(*) from {table}").fetchone(), (1,))
                self.assertEqual(stat.S_IMODE(copy.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(copy.parent.stat().st_mode), 0o700)

    def test_the_panel_row_is_still_in_the_log_alone(self):
        # The premise of the staging test above: without it, a plain file copy
        # would pass that test too
        self.assertGreater(Path(f"{self.panel}-wal").stat().st_size, 0)
        shutil.copyfile(self.panel, self.dir / "main-only.db")
        with closing(sqlite3.connect(self.dir / "main-only.db")) as copy:
            self.assertEqual(copy.execute("select count(*) from sqlite_master").fetchone(), (0,))

    def test_a_store_that_is_not_a_database_stops_the_push(self):
        self.writer.close()
        for log in (f"{self.panel}-wal", f"{self.panel}-shm"):
            Path(log).unlink(missing_ok=True)
        self.panel.write_bytes(b"not a database at all, and long enough to look like a header" * 20)
        result = self.run_script("run")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("backup", [call["argv"][0] for call in self.calls()])

    def test_a_store_with_a_broken_page_stops_the_push(self):
        # .backup copies a damaged b-tree page verbatim and exits 0; only the
        # integrity check on the copy sees it
        with closing(sqlite3.connect(self.metrics)) as db:
            db.execute("create index by_value on samples (value)")
            db.executemany("insert into samples values (?)", [(i * 1.5,) for i in range(5000)])
            db.commit()
            page_size = db.execute("pragma page_size").fetchone()[0]
            pages = db.execute("pragma page_count").fetchone()[0]
        data = bytearray(self.metrics.read_bytes())
        start = page_size * (pages - 2) + 200
        data[start:start + 64] = b"\xff" * 64
        self.metrics.write_bytes(bytes(data))
        result = self.run_script("run")
        self.assertEqual(result.returncode, 1)
        self.assertIn("integrity check", result.stderr)
        self.assertNotIn("backup", [call["argv"][0] for call in self.calls()])

    def test_a_missing_store_stops_the_push(self):
        self.metrics.unlink()
        result = self.run_script("run")
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing", result.stderr)
        self.assertNotIn("backup", [call["argv"][0] for call in self.calls()])

    def test_plain_http_inside_the_tunnel_is_accepted(self):
        for host in ("100.64.0.2", "100.127.255.254", "fd7a:115c:a1e0::9"):
            with self.subTest(host=host):
                result = self.run_script("target", url=http(host))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("inside the tunnel", result.stdout)

    def test_plain_http_outside_the_tunnel_is_refused_before_restic_runs(self):
        # localhost resolves, and resolves outside the ranges
        for host in ("198.51.100.7", "100.128.0.1", "2001:db8::1", "localhost"):
            with self.subTest(host=host):
                for verb in ("target", "init", "run"):
                    result = self.run_script(verb, url=http(host))
                    self.assertEqual(result.returncode, 1, (verb, result.stdout))
                    self.assertIn("outside the tunnel", result.stderr)
                    # The refusal names the way out
                    self.assertIn("https://", result.stderr)
                self.assertEqual(self.calls(), [])

    def test_https_is_accepted_anywhere(self):
        # A public address, a name that resolves nowhere, and the tunnel too:
        # TLS carries its own encryption, so where the station sits is not asked
        for url in ("https://198.51.100.7:8000", "https://backup.invalid", "https://100.64.0.2"):
            with self.subTest(url=url):
                result = self.run_script("target", url=url)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("over HTTPS", result.stdout)
        self.log.unlink(missing_ok=True)
        result = self.run_script("run", url="https://198.51.100.7:8000")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls()[-1]["env"]["RESTIC_REPOSITORY"],
                         "rest:https://198.51.100.7:8000/node-1/")

    def test_a_station_url_of_any_other_shape_is_refused(self):
        for url in ("ftp://100.64.0.2", "100.64.0.2:8000", "http://", "https://node-1:pw@backup.invalid"):
            with self.subTest(url=url):
                result = self.run_script("run", url=url)
                self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(self.calls(), [])

    def test_a_station_that_does_not_resolve_is_refused(self):
        result = self.run_script("target", url=http("station.invalid"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not resolve", result.stderr)

    def test_usage_errors_exit_2_and_help_exits_0(self):
        self.assertEqual(self.run_script().returncode, 2)
        self.assertEqual(self.run_script("prune").returncode, 2)
        self.assertEqual(self.run_script("run", "extra").returncode, 2)
        self.assertEqual(self.run_script("--help").returncode, 0)
        self.assertEqual(self.calls(), [])


CHECK_START = "# --- the backup"
CHECK_END = "# --- the metrics API"

CHECK_STUBS = {
    "systemctl": 'exit "${STUB_TIMER_RC:-0}"',
    "find": 'printf "%b" "${STUB_FIND:-}"',
}


class TestChecker(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        for name, body in CHECK_STUBS.items():
            (self.bin / name).write_text(f"#!/bin/sh\n{body}\n")
            (self.bin / name).chmod(0o755)
        self.config = self.dir / "config"
        self.config.mkdir()
        (self.config / "rest-password").write_text(REST_PASSWORD)
        (self.config / "repository-password").write_text(REPOSITORY_PASSWORD)

    def run_checks(self, url=TUNNEL_URL, env=None):
        # The section asks the real script, rendered for the same station
        script = write_script(self.dir, url)
        values = {
            "backup_url": url,
            "backup_script": str(script),
            "backup_config_dir": str(self.config),
            "backup_state_dir": str(self.dir / "state"),
        }
        source = CHECKER.read_text()
        section = source[source.index(CHECK_START):source.index(CHECK_END)]
        body = Environment(trim_blocks=True, undefined=StrictUndefined).from_string(section).render(**values)
        program = (
            "failures=0\n"
            "fail() { printf 'FAIL %s\\n' \"$*\"; failures=$((failures + 1)); }\n"
            "ok() { printf 'ok   %s\\n' \"$*\"; }\n"
            + body + '\nexit "$failures"\n'
        )
        environ = {**os.environ, **(env or {})}
        environ["PATH"] = f"{self.bin}:{environ['PATH']}"
        result = subprocess.run(["bash", "-c", program], capture_output=True, text=True,
                                env=environ, check=False)
        self.assertEqual(result.stderr, "")
        lines = result.stdout.splitlines()
        return result.returncode, [line for line in lines if line.startswith("FAIL")], lines

    def assert_one_failure(self, needle, **kwargs):
        failures, lines, _ = self.run_checks(**kwargs)
        self.assertEqual(failures, 1, lines)
        self.assertIn(needle, lines[0])

    def test_a_healthy_backup_passes_with_each_check_said(self):
        failures, fails, lines = self.run_checks()
        self.assertEqual((failures, fails), (0, []))
        self.assertEqual(len([line for line in lines if line.startswith("ok")]), 3, lines)

    def test_a_timer_that_is_not_running_fails(self):
        self.assert_one_failure("backup timer is not enabled", env={"STUB_TIMER_RC": "3"})

    def test_plain_http_outside_the_tunnel_fails(self):
        self.assert_one_failure("outside the tunnel", url=http("198.51.100.7"))

    def test_https_outside_the_tunnel_passes(self):
        failures, fails, lines = self.run_checks(url="https://198.51.100.7:8000")
        self.assertEqual((failures, fails), (0, []))
        self.assertTrue(any("over HTTPS" in line for line in lines), lines)

    def test_anything_open_beyond_root_fails(self):
        self.assert_one_failure("open beyond root", env={"STUB_FIND": "/var/lib/skibidi-backup/staging\\n"})

    def test_missing_secrets_fail(self):
        (self.config / "repository-password").unlink()
        self.assert_one_failure("secrets are missing")

    def test_the_timer_the_role_installs_is_one_the_checker_watches(self):
        watched = yaml.safe_load((ROOT / "roles" / "checker" / "defaults" / "main.yml").read_text())
        installed = {path.name.removesuffix(".j2") for path in (ROLE / "templates").glob("*.timer.j2")}
        self.assertEqual(len(installed), 1)
        self.assertLessEqual(installed, {timer["name"] for timer in watched["checker_watched_timers"]})

    def test_a_node_without_a_station_checks_nothing(self):
        # An empty URL, and none at all for a play that never loaded the role.
        # Strict, so a backup variable read outside the guard fails here
        source = CHECKER.read_text()
        section = source[source.index(CHECK_START):source.index(CHECK_END)]
        template = Environment(trim_blocks=True, undefined=StrictUndefined).from_string(section)
        for values in ({"backup_url": ""}, {}):
            with self.subTest(values=values):
                body = template.render(**values)
                self.assertNotIn("backup", "\n".join(
                    line for line in body.splitlines() if not line.startswith("#")))


def tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise AssertionError(f"{name} is not on PATH; run the suite inside `nix develop .#ci`")
    return path


def free_port() -> int:
    with closing(socket.socket()) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class TestRealStation(unittest.TestCase):
    """The rendered script, the real restic and a real rest-server.

    The server runs the way the station's contract says: append-only, one
    private repository per account. It listens on loopback, so the test widens
    the tunnel ranges to loopback rather than weakening the guard.
    """

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.restic = tool("restic")

        # rest-server accepts {SHA} lines; bcrypt would need a tool the shell
        # does not carry, and the hash shape is not what is under test
        self.station = self.dir / "station"
        self.station.mkdir()
        lines = [f"{user}:{{SHA}}" + base64.b64encode(hashlib.sha1(password.encode()).digest()).decode()
                 for user, password in (("node-1", REST_PASSWORD), ("node-2", "other"))]
        (self.station / ".htpasswd").write_text("\n".join(lines) + "\n")
        port = free_port()
        self.url = f"http://127.0.0.1:{port}"
        server = subprocess.Popen(
            [tool("rest-server"), "--path", str(self.station), "--listen", f"127.0.0.1:{port}",
             "--append-only", "--private-repos"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(server.wait)
        self.addCleanup(server.terminate)
        deadline = time.monotonic() + 10
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise AssertionError("rest-server did not start listening") from None
                time.sleep(0.05)

        self.config = self.dir / "config"
        self.config.mkdir(mode=0o700)
        (self.config / "rest-password").write_text(REST_PASSWORD)
        (self.config / "repository-password").write_text(REPOSITORY_PASSWORD)

        # The panel's row lives in its write-ahead log alone, as in TestScript
        self.panel = self.dir / "etc" / "x-ui" / "x-ui.db"
        self.panel.parent.mkdir(parents=True)
        self.writer = sqlite3.connect(self.panel)
        self.addCleanup(self.writer.close)
        self.writer.execute("pragma journal_mode=wal")
        self.writer.execute("pragma wal_autocheckpoint=0")
        self.writer.execute("create table settings (key text, value text)")
        self.writer.execute("insert into settings values ('webPort', '2053')")
        self.writer.commit()

        self.script = write_script(
            self.dir, self.url,
            backup_restic_path=self.restic,
            backup_tunnel_ranges=["127.0.0.0/8"],
            backup_databases=[str(self.panel)],
        )

    def run_script(self, *args):
        return subprocess.run([str(self.script), *args], capture_output=True, text=True, check=False)

    def as_node(self, *args, repository="node-1"):
        """restic as the node, with the node's own credentials."""
        env = {
            **os.environ,
            "RESTIC_REPOSITORY": f"rest:{self.url}/{repository}/",
            "RESTIC_REST_USERNAME": "node-1",
            "RESTIC_REST_PASSWORD": REST_PASSWORD,
            "RESTIC_PASSWORD_FILE": str(self.config / "repository-password"),
            "RESTIC_CACHE_DIR": str(self.dir / "cache"),
        }
        return subprocess.run([self.restic, *args], capture_output=True, text=True, env=env,
                              check=False)

    def snapshots(self) -> list[str]:
        directory = self.station / "node-1" / "snapshots"
        return sorted(path.name for path in directory.iterdir()) if directory.exists() else []

    def test_init_creates_the_repository_once(self):
        first = self.run_script("init")
        self.assertEqual((first.returncode, first.stdout.strip()), (0, "created the repository"),
                         first.stderr)
        self.assertTrue((self.station / "node-1" / "config").is_file())
        second = self.run_script("init")
        self.assertEqual((second.returncode, second.stdout.strip()), (0, "the repository exists"),
                         second.stderr)

    def test_a_push_arrives_and_restores_whole(self):
        result = self.run_script("run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.snapshots()), 1)
        target = self.dir / "restored"
        restore = self.as_node("restore", "latest", "--target", str(target))
        self.assertEqual(restore.returncode, 0, restore.stderr)
        copy = Path(f"{target}{self.dir}/state/staging{self.panel}")
        with closing(sqlite3.connect(copy)) as db:
            self.assertEqual(db.execute("pragma integrity_check").fetchone(), ("ok",))
            self.assertEqual(db.execute("select value from settings where key = 'webPort'").fetchall(),
                             [("2053",)])

    def test_the_node_cannot_delete_what_it_pushed(self):
        self.assertEqual(self.run_script("run").returncode, 0)
        pushed = self.snapshots()
        self.assertEqual(len(pushed), 1)
        forget = self.as_node("forget", pushed[0])
        self.assertNotEqual(forget.returncode, 0)
        self.assertIn("403", forget.stderr)
        self.assertEqual(self.snapshots(), pushed)

    def test_the_node_cannot_reach_another_node_repository(self):
        other = self.as_node("init", repository="node-2")
        self.assertNotEqual(other.returncode, 0)
        self.assertFalse((self.station / "node-2").exists())

    def test_a_wrong_station_password_creates_nothing(self):
        (self.config / "rest-password").write_text("not the station password")
        result = self.run_script("run")
        self.assertEqual(result.returncode, 1)
        self.assertIn("cannot open the repository", result.stderr)
        self.assertFalse((self.station / "node-1").exists())

    def test_a_wrong_repository_password_is_not_answered_with_a_new_repository(self):
        self.assertEqual(self.run_script("init").returncode, 0)
        config = (self.station / "node-1" / "config").read_bytes()
        (self.config / "repository-password").write_text("not the repository password")
        result = self.run_script("run")
        self.assertEqual(result.returncode, 1)
        self.assertIn("cannot open the repository", result.stderr)
        self.assertEqual((self.station / "node-1" / "config").read_bytes(), config)
        self.assertEqual(self.snapshots(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
