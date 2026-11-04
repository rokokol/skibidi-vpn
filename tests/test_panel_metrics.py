from __future__ import annotations

import json
import sqlite3
import threading
import time
import unittest
from importlib import import_module
from unittest.mock import Mock, patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from test_collector_push import PushCase


class TestPanelMetrics(PushCase):
    def setUp(self):
        super().setUp()
        self.requests = []
        self.responses = {
            "server/status": (200, {"success": True, "obj": {"xray": {"state": "running"}}}),
            "server/history/online/2": (200, {"success": True, "obj": [{"t": time.time(), "v": 3}]}),
        }
        case = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                case.requests.append((self.path, self.headers.get("Authorization")))
                status, body = case.responses.get(self.path.removeprefix("/hidden/panel/api/"), (404, {}))
                self.send_response(status)
                if status == 302:
                    self.send_header("Location", "/credential-trap")
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join()))
        self.config = self.dir / "panel.json"
        self.settings = {"url": f"http://127.0.0.1:{server.server_port}/hidden", "token": "monitor-only-fixture"}
        self.save_config()
        import os
        os.environ["SKIBIDI_PANEL_CONFIG"] = str(self.config)
        self.rows = [("load1", "", 0.5)]

    def save_config(self):
        self.config.write_text(json.dumps(self.settings))
        self.config.chmod(0o600)

    def panel_values(self):
        code, errors = self.collect()
        self.assertEqual(code, 0, errors)
        return {name: family["samples"][0][1] for name, family in self.pushed().items() if name.startswith("x_ui_")}

    def test_current_panel_values_reach_the_existing_push_group(self):
        self.assertEqual(self.panel_values(), {"x_ui_panel_up": 1, "x_ui_xray_up": 1, "x_ui_online_clients": 3})
        self.assertTrue(self.requests)
        self.assertTrue(all(auth == "Bearer monitor-only-fixture" for _, auth in self.requests))
        self.assertEqual(self.pushed()["vpn_load1"]["samples"], [({}, 0.5)])

    def test_a_stopped_core_is_not_a_dead_panel(self):
        self.responses["server/status"][1]["obj"]["xray"]["state"] = "stop"
        self.assertEqual(self.panel_values().get("x_ui_xray_up"), 0)
        self.assertEqual(self.panel_values().get("x_ui_panel_up"), 1)

    def test_an_unreachable_api_does_not_claim_the_core_stopped(self):
        self.responses["server/status"] = (503, {"secret": "never-log-response-body"})
        self.assertEqual(self.panel_values(), {"x_ui_panel_up": 0})
        self.assertEqual(len(self.requests), 1)

    def test_failed_status_removes_the_previous_core_value(self):
        self.panel_values()
        self.responses["server/status"] = (401, {})
        self.assertEqual(self.panel_values(), {"x_ui_panel_up": 0})

    def test_an_unknown_process_state_is_not_reported_as_healthy(self):
        self.responses["server/status"][1]["obj"]["xray"]["state"] = "unexpected"
        self.assertNotIn("x_ui_xray_up", self.panel_values())

    def test_a_refused_json_envelope_is_not_a_success(self):
        self.responses["server/status"] = (200, {"success": False, "obj": {"xray": {"state": "running"}}})
        self.assertEqual(self.panel_values(), {"x_ui_panel_up": 0})

    def test_stale_online_history_is_not_current_online(self):
        self.responses["server/history/online/2"][1]["obj"] = [{"t": time.time() - 90, "v": 8}]
        self.assertNotIn("x_ui_online_clients", self.panel_values())

    def test_empty_online_history_is_not_zero_clients(self):
        self.responses["server/history/online/2"][1]["obj"] = []
        self.assertNotIn("x_ui_online_clients", self.panel_values())

    def test_zero_online_is_a_real_sample(self):
        self.responses["server/history/online/2"][1]["obj"][0]["v"] = 0
        self.assertEqual(self.panel_values().get("x_ui_online_clients"), 0)

    def test_bad_online_values_cannot_reach_the_gateway(self):
        for value in (-1, float("nan"), float("inf"), True, "4"):
            with self.subTest(value=value):
                self.responses["server/history/online/2"][1]["obj"][0]["v"] = value
                self.assertNotIn("x_ui_online_clients", self.panel_values())

    def test_a_redirect_never_receives_the_token(self):
        self.responses["server/status"] = (302, {})
        self.assertEqual(self.panel_values(), {"x_ui_panel_up": 0})
        self.assertEqual(len(self.requests), 1)

    def test_a_readable_config_is_refused_before_network_access(self):
        self.config.chmod(0o644)
        self.assertEqual(self.panel_values(), {"x_ui_panel_up": 0})
        self.assertEqual(self.requests, [])

    def test_cleartext_remote_urls_are_refused_before_network_access(self):
        self.settings["url"] = "http://192.0.2.1:2053/hidden"
        self.save_config()
        self.assertEqual(self.panel_values(), {"x_ui_panel_up": 0})
        self.assertEqual(self.requests, [])

    def test_errors_never_print_the_token_base_path_or_response_body(self):
        self.responses["server/status"] = (403, {"msg": "never-log-response-body"})
        code, errors = self.collect()
        self.assertEqual(code, 0)
        self.assertIn("panel", errors)
        for secret in (self.settings["token"], "hidden", "never-log-response-body"):
            self.assertNotIn(secret, errors)


class TestPanelTLS(unittest.TestCase):
    def test_cleartext_accepts_an_address_assigned_to_this_host(self):
        skibidi_panel = import_module("skibidi_panel")

        probe = Mock()
        probe.__enter__ = Mock(return_value=probe)
        probe.__exit__ = Mock(return_value=False)
        probe.getsockname.return_value = ("192.0.2.7", 40000)
        with patch.object(skibidi_panel.socket, "socket", return_value=probe):
            self.assertTrue(skibidi_panel.local_address("192.0.2.7"))
            self.assertFalse(skibidi_panel.local_address("192.0.2.8"))


    def test_a_bad_certificate_pin_stops_the_request_before_the_token(self):
        skibidi_panel = import_module("skibidi_panel")
        from urllib.parse import urlsplit

        connection = Mock()
        connection.sock.getpeercert.return_value = b"other certificate"
        settings = (urlsplit("https://panel.example/hidden"), "monitor-only-fixture", "0" * 64)
        with patch.object(skibidi_panel.http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaises(skibidi_panel.PanelError):
                skibidi_panel.api_get(settings, "server/status")
        connection.connect.assert_called_once()
        connection.request.assert_not_called()
        connection.close.assert_called_once()

    def test_a_matching_pin_allows_the_authenticated_request(self):
        import hashlib
        skibidi_panel = import_module("skibidi_panel")
        from urllib.parse import urlsplit

        connection = Mock()
        certificate = b"trusted certificate"
        connection.sock.getpeercert.return_value = certificate
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.read.return_value = b'{"success":true,"obj":{"ok":1}}'
        settings = (urlsplit("https://panel.example/hidden"), "monitor-only-fixture", hashlib.sha256(certificate).hexdigest())
        with patch.object(skibidi_panel.http.client, "HTTPSConnection", return_value=connection):
            self.assertEqual(skibidi_panel.api_get(settings, "server/status"), {"ok": 1})
        self.assertEqual(connection.request.call_args.kwargs["headers"]["Authorization"], "Bearer monitor-only-fixture")


class TestCollectorConnections(PushCase):
    def test_collection_and_push_close_their_connections(self):
        connections = []
        original = self.module.connect

        def connect():
            connection = original()
            connections.append(connection)
            self.addCleanup(connection.close)
            return connection

        self.rows = [("load1", "", 0.5)]
        with patch.object(self.module, "connect", connect):
            self.assertEqual(self.collect()[0], 0)
        self.assertTrue(connections)
        for connection in connections:
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")


if __name__ == "__main__":
    unittest.main()
