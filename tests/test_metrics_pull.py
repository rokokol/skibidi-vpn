"""The letter's pull, run against the node's real API.

The reporter and the API ship to different hosts, so the contract between them
is only ever exercised on Monday morning. Here both halves run in one process:
the metrics handler serves a throwaway store on loopback, and the reporter's
own pull_node, probe and gather_metrics read it the way the master reads the
fleet over the tailnet.
"""

from __future__ import annotations

import importlib.util
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

os.environ.setdefault("MPLCONFIGDIR", tempfile.mkdtemp(prefix="skibidi-mpl-"))
os.environ.setdefault("SKIBIDI_MAIL_FILE", "/nonexistent/ddlc-mail.json")


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


report = load("skibidi_report", "roles/reporter/files/skibidi-report.py")

HOUR_US = 3600 * 1_000_000
END_US = 1_790_000_000 // 3600 * 3600 * 1_000_000
START_US = END_US - 168 * HOUR_US


def closed_port() -> int:
    # Bound and never listened on, so a connection is refused at once rather
    # than left to time out
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class PullCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "metrics.db"
        os.environ["SKIBIDI_METRICS_DB"] = str(self.db)
        self.addCleanup(os.environ.pop, "SKIBIDI_METRICS_DB", None)
        self.metrics = load("skibidi_metrics", "roles/metrics/files/skibidi-metrics.py")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.metrics.handler_for(self.db))
        threading.Thread(target=self.server.serve_forever, args=(0.01,), daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]

    def write(self, rows, collected_through_us):
        with self.metrics.connect() as connection:
            connection.executemany(
                "INSERT INTO samples (ts_us, metric, detail, value) VALUES (?, ?, ?, ?)", rows
            )
            connection.execute(
                "INSERT OR REPLACE INTO state (key, value) VALUES ('collected_through_us', ?)",
                (str(collected_through_us),),
            )
        connection.close()

    def config(self, *nodes):
        return {"metrics": {"port": self.port}, "nodes": list(nodes)}


class TestPullNode(PullCase):
    def test_the_window_arrives_as_the_samples_the_letter_reads(self):
        self.write(
            [
                (START_US - 1, "load1", "", 9.0),
                (START_US, "f2b_banned_total", "sshd", 10.0),
                (START_US + HOUR_US, "f2b_banned_total", "sshd", 14.0),
                (END_US, "load1", "", 9.0),
            ],
            collected_through_us=END_US,
        )
        node = {"name": "alpha", "host": "127.0.0.1"}
        export = report.pull_node(self.config(node), node, START_US, END_US)
        self.assertEqual(export["collected_through_us"], END_US)
        self.assertEqual(
            [list(row) for row in export["samples"]],
            [
                [START_US, "f2b_banned_total", "sshd", 10.0],
                [START_US + HOUR_US, "f2b_banned_total", "sshd", 14.0],
            ],
        )
        self.assertEqual(report.counter_week_delta(export, "f2b_banned_total", "sshd"), 4)

    def test_a_node_that_does_not_answer_is_a_stale_window(self):
        node = {"name": "alpha", "host": "127.0.0.1"}
        config = {"metrics": {"port": closed_port()}, "nodes": [node]}
        with self.assertRaises(report.StaleWindow):
            report.pull_node(config, node, START_US, END_US)

    def test_an_error_status_is_a_stale_window_that_says_why(self):
        # No store at all: the API answers 503, and the reason must reach the
        # letter rather than an empty week that reads as a quiet node
        node = {"name": "alpha", "host": "127.0.0.1"}
        with self.assertRaises(report.StaleWindow) as caught:
            report.pull_node(self.config(node), node, START_US, END_US)
        self.assertIn("503", str(caught.exception))
        self.assertFalse(self.db.exists())

    def test_a_cut_answer_is_refused_rather_than_read_as_the_week(self):
        self.write([(START_US + n, "load1", "", 1.0) for n in range(3)], END_US)
        self.metrics.SAMPLES_LIMIT = 2
        node = {"name": "alpha", "host": "127.0.0.1"}
        with self.assertRaises(report.StaleWindow):
            report.pull_node(self.config(node), node, START_US, END_US)


class TestGather(PullCase):
    def test_the_master_is_pulled_like_any_node_and_silence_is_named(self):
        self.write([(START_US, "load1", "", 0.5)], collected_through_us=END_US)
        master = {"name": "master", "host": "127.0.0.1"}
        # Another loopback address: the API listens on 127.0.0.1 alone, so
        # this one refuses on the same port
        dead = {"name": "beta", "host": "127.0.0.2"}
        exports, unreachable, stale = report.gather_metrics(self.config(master, dead), START_US, END_US)
        self.assertEqual(list(exports), ["master"])
        self.assertEqual([name for name, _reason in unreachable], ["beta"])
        self.assertEqual(stale, [])

    def test_a_node_whose_collector_stopped_is_stale(self):
        self.write([(START_US, "load1", "", 0.5)], collected_through_us=START_US)
        node = {"name": "alpha", "host": "127.0.0.1"}
        _exports, unreachable, stale = report.gather_metrics(self.config(node), START_US, END_US)
        self.assertEqual((unreachable, stale), ([], ["alpha"]))

    def test_the_letter_waits_for_the_master_to_cross_the_window(self):
        self.write([], collected_through_us=END_US)
        config = self.config({"name": "master", "host": "127.0.0.1"})
        self.assertTrue(report.wait_for_collector(config, "master", END_US, time.monotonic() + 5))

    def test_a_master_behind_the_window_is_waited_for_then_reported_partial(self):
        self.write([], collected_through_us=END_US - HOUR_US)
        config = self.config({"name": "master", "host": "127.0.0.1"})
        self.assertFalse(report.wait_for_collector(config, "master", END_US, time.monotonic() + 0.2, 0.05))


class TestProbe(PullCase):
    def test_an_answering_node_passes_the_probe(self):
        self.write([], collected_through_us=END_US)
        self.assertEqual(report.probe(self.config({"name": "alpha", "host": "127.0.0.1"})), 0)

    def test_a_silent_node_fails_the_probe(self):
        node = {"name": "alpha", "host": "127.0.0.2"}
        self.assertEqual(report.probe(self.config(node)), 1)

    def test_a_node_without_a_store_fails_the_probe(self):
        self.assertEqual(report.probe(self.config({"name": "alpha", "host": "127.0.0.1"})), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
