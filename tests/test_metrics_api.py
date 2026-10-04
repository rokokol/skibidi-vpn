"""The HTTP API a node serves its metric store through, on the tailnet.

It replaced an SSH export whose forced-command guard was the one thing between
a key and a shell. The API has no shell to guard, so what is under test is the
contract a reader depends on: which rows a window returns, how a cumulative
counter becomes a delta, which requests are refused and with what status, and
that the store is only ever opened read-only.

Each test runs the real handler over a real socket against a throwaway store.
"""

from __future__ import annotations

import http.client
import importlib.util
import json
import os
import socket
import sqlite3
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "roles" / "metrics" / "files" / "skibidi-metrics.py"

HOUR = 3600
DAY = 86400
# A fixed origin on a day boundary, so bucket arithmetic in the tests is
# readable: T0 is a UTC midnight
T0 = 1_790_000_000 - 1_790_000_000 % DAY


def load():
    spec = importlib.util.spec_from_file_location("skibidi_metrics", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["skibidi_metrics"] = module
    spec.loader.exec_module(module)
    return module


def us(seconds: float) -> int:
    return int(seconds * 1_000_000)


class ApiCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "metrics.db"
        os.environ["SKIBIDI_METRICS_DB"] = str(self.db)
        self.addCleanup(os.environ.pop, "SKIBIDI_METRICS_DB", None)
        self.module = load()
        self.server = None

    def write(self, rows, collected_through_us=None):
        with self.module.connect() as connection:
            connection.executemany(
                "INSERT INTO samples (ts_us, metric, detail, value) VALUES (?, ?, ?, ?)", rows
            )
            if collected_through_us is not None:
                connection.execute(
                    "INSERT OR REPLACE INTO state (key, value) VALUES ('collected_through_us', ?)",
                    (str(collected_through_us),),
                )
        connection.close()

    def start(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.module.handler_for(self.db))
        # A short poll, or every shutdown waits out the default half second
        thread = threading.Thread(target=self.server.serve_forever, args=(0.01,), daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, path, method="GET"):
        if self.server is None:
            self.start()
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=10)
        self.addCleanup(connection.close)
        connection.request(method, path)
        response = connection.getresponse()
        body = response.read()
        payload = json.loads(body) if response.getheader("Content-Type") == "application/json" else body
        return response.status, payload, response


class TestHealth(ApiCase):
    def test_a_store_the_collector_never_finished_is_starting(self):
        self.write([])
        status, payload, _ = self.request("/v1/health")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "starting")
        self.assertIsNone(payload["collected_through_us"])

    def test_a_collected_store_is_ok_and_says_how_far_it_got(self):
        self.write(
            [(us(T0), "load1", "", 0.5), (us(T0 + 600), "load1", "", 0.7)],
            collected_through_us=us(T0 + 600),
        )
        status, payload, _ = self.request("/v1/health")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["collected_through_us"], us(T0 + 600))
        self.assertEqual(payload["samples"], 2)
        self.assertEqual(payload["samples_oldest_us"], us(T0))
        self.assertEqual(payload["samples_newest_us"], us(T0 + 600))
        self.assertGreaterEqual(payload["collection_lag_seconds"], 0)

    def test_a_missing_store_is_unavailable_and_is_not_created(self):
        # A read-write open would conjure an empty store here, turning "the
        # collector never ran" into a healthy-looking node with no rows
        status, payload, _ = self.request("/v1/health")
        self.assertEqual(status, 503)
        self.assertIn("error", payload)
        self.assertFalse(self.db.exists(), "the API created the store it failed to read")


class TestSamples(ApiCase):
    def test_the_window_is_half_open_and_nothing_outside_it_leaks(self):
        self.write(
            [
                (us(T0 - 1), "load1", "", 9.0),
                (us(T0), "load1", "", 1.0),
                (us(T0 + HOUR - 1), "load1", "", 2.0),
                (us(T0 + HOUR), "load1", "", 9.0),
            ],
            collected_through_us=us(T0 + HOUR),
        )
        status, payload, _ = self.request(f"/v1/samples?from={T0}&to={T0 + HOUR}")
        self.assertEqual(status, 200)
        self.assertEqual([row["value"] for row in payload["rows"]], [1.0, 2.0])
        self.assertEqual((payload["from"], payload["to"]), (T0, T0 + HOUR))
        self.assertFalse(payload["truncated"])
        self.assertEqual(payload["collected_through_us"], us(T0 + HOUR))

    def test_a_row_names_its_dimension_and_keeps_microseconds(self):
        self.write([(us(T0) + 7, "f2b_banned_total", "sshd", 3.0), (us(T0) + 8, "load1", "", 0.1)])
        _, payload, _ = self.request(f"/v1/samples?from={T0}&to={T0 + 60}")
        self.assertEqual(
            payload["rows"],
            [
                {"ts_us": us(T0) + 7, "metric": "f2b_banned_total",
                 "dimensions": {"jail": "sshd"}, "value": 3.0},
                {"ts_us": us(T0) + 8, "metric": "load1", "dimensions": {}, "value": 0.1},
            ],
        )

    def test_the_metric_parameter_selects_one_metric(self):
        self.write([(us(T0), "load1", "", 0.1), (us(T0), "mem_used_ratio", "", 0.5)])
        _, payload, _ = self.request(f"/v1/samples?from={T0}&to={T0 + 60}&metric=mem_used_ratio")
        self.assertEqual([row["metric"] for row in payload["rows"]], ["mem_used_ratio"])

    def test_the_default_window_is_the_last_day(self):
        self.write([(us(T0 - DAY - 1), "load1", "", 9.0), (us(T0 - 10), "load1", "", 1.0)])
        self.module.now_seconds = lambda: T0
        _, payload, _ = self.request("/v1/samples")
        self.assertEqual((payload["from"], payload["to"]), (T0 - DAY, T0))
        self.assertEqual([row["value"] for row in payload["rows"]], [1.0])

    def test_a_cut_answer_says_it_was_cut(self):
        self.write([(us(T0 + n), "load1", "", float(n)) for n in range(5)])
        self.module.SAMPLES_LIMIT = 3
        _, payload, _ = self.request(f"/v1/samples?from={T0}&to={T0 + 60}")
        self.assertTrue(payload["truncated"])
        self.assertEqual(len(payload["rows"]), 3)

    def test_a_bad_window_is_refused_with_a_reason(self):
        self.write([])
        for query in (
            f"from={T0}&to={T0}",
            f"from={T0 + 1}&to={T0}",
            f"from={T0}&to={T0 + 32 * DAY}",
            "from=yesterday",
            f"from={T0}.5&to={T0 + 60}",
        ):
            with self.subTest(query=query):
                status, payload, _ = self.request(f"/v1/samples?{query}")
                self.assertEqual(status, 400)
                self.assertIsInstance(payload["error"], str)


class TestAggregates(ApiCase):
    def test_gauges_are_bucketed_with_count_sum_and_extremes(self):
        self.write([
            (us(T0 + 10), "load1", "", 1.0),
            (us(T0 + 20), "load1", "", 3.0),
            (us(T0 + HOUR + 10), "load1", "", 5.0),
        ])
        status, payload, _ = self.request(f"/v1/aggregates?resolution=hour&from={T0}&to={T0 + 2 * HOUR}")
        self.assertEqual(status, 200)
        self.assertEqual(payload["resolution"], "hour")
        self.assertEqual(
            payload["rows"],
            [
                {"bucket_start": T0, "metric": "load1", "kind": "gauge", "dimensions": {},
                 "samples": 2, "total": 4.0, "minimum": 1.0, "maximum": 3.0},
                {"bucket_start": T0 + HOUR, "metric": "load1", "kind": "gauge", "dimensions": {},
                 "samples": 1, "total": 5.0, "minimum": 5.0, "maximum": 5.0},
            ],
        )

    def test_counters_become_reset_tolerant_deltas_from_the_sample_before(self):
        # 10 before the window is the baseline. Steps: +4 (14), a reset to 2
        # counts as 2, then +1. A reader of raw totals would see 14, 2 and 3
        self.write([
            (us(T0 - 600), "f2b_banned_total", "sshd", 10.0),
            (us(T0 + 600), "f2b_banned_total", "sshd", 14.0),
            (us(T0 + 1200), "f2b_banned_total", "sshd", 2.0),
            (us(T0 + HOUR + 600), "f2b_banned_total", "sshd", 3.0),
        ])
        _, payload, _ = self.request(f"/v1/aggregates?resolution=hour&from={T0}&to={T0 + 2 * HOUR}")
        rows = [(r["bucket_start"], r["kind"], r["samples"], r["total"], r["minimum"], r["maximum"])
                for r in payload["rows"]]
        self.assertEqual(rows, [
            (T0, "counter", 2, 6.0, 2.0, 4.0),
            (T0 + HOUR, "counter", 1, 1.0, 1.0, 1.0),
        ])
        self.assertEqual(payload["rows"][0]["dimensions"], {"jail": "sshd"})

    def test_a_counter_series_is_its_own_series_per_dimension(self):
        self.write([
            (us(T0 + 10), "unit_restarts", "nginx", 1.0),
            (us(T0 + 20), "unit_restarts", "x-ui", 5.0),
            (us(T0 + 30), "unit_restarts", "nginx", 2.0),
            (us(T0 + 40), "unit_restarts", "x-ui", 5.0),
        ])
        _, payload, _ = self.request(f"/v1/aggregates?resolution=day&from={T0}&to={T0 + DAY}")
        totals = {r["dimensions"]["unit"]: r["total"] for r in payload["rows"]}
        self.assertEqual(totals, {"nginx": 1.0, "x-ui": 0.0})

    def test_day_buckets_start_on_utc_midnight(self):
        self.write([(us(T0 + DAY + 5 * HOUR), "load1", "", 1.0)])
        _, payload, _ = self.request(f"/v1/aggregates?resolution=day&from={T0}&to={T0 + 3 * DAY}")
        self.assertEqual([r["bucket_start"] for r in payload["rows"]], [T0 + DAY])

    def test_a_bucket_is_in_the_answer_when_its_start_is_in_the_window(self):
        # The mail host's rule: buckets are selected by where they start, so
        # a from inside an hour skips that hour rather than half-counting it
        self.write([(us(T0 + 10), "load1", "", 9.0), (us(T0 + HOUR + 10), "load1", "", 1.0)])
        _, payload, _ = self.request(
            f"/v1/aggregates?resolution=hour&from={T0 + 5}&to={T0 + 2 * HOUR}"
        )
        self.assertEqual([r["bucket_start"] for r in payload["rows"]], [T0 + HOUR])

    def test_an_unknown_resolution_is_refused(self):
        self.write([])
        status, payload, _ = self.request(f"/v1/aggregates?resolution=minute&from={T0}&to={T0 + 60}")
        self.assertEqual(status, 400)
        self.assertIn("resolution", payload["error"])

    def test_the_metric_parameter_selects_one_metric(self):
        self.write([(us(T0 + 10), "load1", "", 1.0), (us(T0 + 10), "mem_used_ratio", "", 0.5)])
        _, payload, _ = self.request(
            f"/v1/aggregates?resolution=hour&from={T0}&to={T0 + HOUR}&metric=load1"
        )
        self.assertEqual({r["metric"] for r in payload["rows"]}, {"load1"})


class TestRouting(ApiCase):
    def test_everything_else_is_not_found(self):
        self.write([])
        for path in ("/", "/v1", "/v2/health", "/v1/health/x", "/v1/export"):
            with self.subTest(path=path):
                status, payload, _ = self.request(path)
                self.assertEqual(status, 404)
                self.assertEqual(payload, {"error": "not found"})

    def test_only_get_is_served(self):
        self.write([])
        for method in ("POST", "PUT", "DELETE"):
            with self.subTest(method=method):
                status, _, _ = self.request("/v1/health", method=method)
                self.assertEqual(status, 501)

    def test_answers_are_json_and_never_cached(self):
        self.write([])
        _, _, response = self.request("/v1/health")
        self.assertEqual(response.getheader("Content-Type"), "application/json")
        self.assertEqual(response.getheader("Cache-Control"), "no-store")


class TestSocketActivation(ApiCase):
    def test_one_connection_handed_over_is_answered_and_closed(self):
        # systemd hands each accepted connection to a fresh process on fd 0;
        # serve_connection is that process's whole life
        self.write([], collected_through_us=us(T0))
        ours, theirs = socket.socketpair()
        self.addCleanup(ours.close)
        worker = threading.Thread(target=self.module.serve_connection, args=(theirs,))
        worker.start()
        ours.sendall(b"GET /v1/health HTTP/1.0\r\nHost: node\r\n\r\n")
        answer = b""
        while chunk := ours.recv(65536):
            answer += chunk
        worker.join(5)
        self.assertFalse(worker.is_alive(), "the worker kept the connection open")
        head, _, body = answer.partition(b"\r\n\r\n")
        self.assertIn(b" 200 ", head.split(b"\r\n")[0])
        self.assertEqual(json.loads(body)["status"], "ok")


class TestReadOnly(ApiCase):
    def test_the_readonly_connection_refuses_writes(self):
        self.write([(1, "load1", "", 0.5)])
        with self.module.readonly_connection() as readonly:
            with self.assertRaises(sqlite3.OperationalError):
                readonly.execute(
                    "INSERT INTO samples (ts_us, metric, detail, value) VALUES (2, 'load1', '', 1.0)"
                )

    def test_the_ssh_entry_points_are_gone(self):
        # The SSH export was removed with its key; an entry point left behind
        # would be a door nobody watches any more
        for argv in (["ssh-guard"], ["export", "--since", "0", "--until", "1"]):
            with self.subTest(argv=argv):
                self.assertEqual(self.module.main(argv), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
