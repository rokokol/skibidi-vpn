"""The letter, proven on synthetic data — no panel, no fleet, no VM.

Two assertions are lifted from the mail host's report before anything else,
because both have failed there in the past: the cid round trip (every cid:
referenced by the HTML has a matching attachment and vice versa) and the
empty week (no data must still produce a letter, with an Overview and no
dangling references).
"""

from __future__ import annotations

import datetime as dt
import html
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from zoneinfo import ZoneInfo

# Before any chart renders: the deployed unit points this at the state dir,
# and a test run must not try to write /var/lib
os.environ["MPLCONFIGDIR"] = tempfile.mkdtemp(prefix="skibidi-mpl-")

SCRIPT = (
    Path(__file__).resolve().parent.parent
    / "roles" / "reporter" / "files" / "skibidi-report.py"
)
specification = importlib.util.spec_from_file_location("skibidi_report", SCRIPT)
report = importlib.util.module_from_spec(specification)
sys.modules["skibidi_report"] = report
specification.loader.exec_module(report)

ZONE = ZoneInfo("Europe/Moscow")


def empty_data():
    start = dt.datetime(2026, 8, 24, 9, tzinfo=ZONE)
    end = dt.datetime(2026, 8, 31, 9, tzinfo=ZONE)
    return {
        "start": start,
        "end": end,
        "timezone": "Europe/Moscow",
        "days": [start.date() + dt.timedelta(days=n) for n in range(7)],
    }


def busy_data():
    data = empty_data()
    data["inbound_series"] = [
        (data["start"].date() + dt.timedelta(days=n), {"SE-exit": (n + 1) * 2**30})
        for n in range(7)
    ]
    data["client_deltas"] = [("Art****", 5 * 2**30), ("Mo*", 2**30)]
    data["bans_by_day"] = {data["start"].date(): 4}
    data["drops_by_day"] = {data["start"].date(): 120}
    data["exports"] = {
        "se-1": {
            "collected_through_us": 10**18,
            "samples": [[10**15, "load1", "", 0.5], [2 * 10**15, "load1", "", 1.5]],
        }
    }
    data["health"] = report.health_rows(data["exports"])
    data["alerts"] = ["node ru-msk-1 did not answer the metrics pull"]
    data["panel"] = {
        "nodes": [{"name": "ru-msk-1", "online": True, "heartbeat": 0,
                   "latency_ms": 42, "cpu": 1, "mem": 20,
                   "panel_version": "3.7.0", "xray_version": "25.1.1"}],
        "clients": [{"label": "<script>alert(1)</script>", "inbound": "SE-exit",
                     "enable": True, "silent_days": 45.0,
                     "cap_share": None, "expires_days": None}],
        "versions": {"master": {"panel": "3.7.0", "xray": "25.1.1"}},
    }
    data["changes"] = ["inbound added: Тест-инбаунд"]
    return data


def cids_referenced(html_body: str) -> set[str]:
    return set(re.findall(r'src="cid:([^"]+)"', html_body))


def parts_of(message):
    payload = message.get_payload()
    html_part = payload[-1]
    if html_part.get_content_type() == "multipart/related":
        related = html_part.get_payload()
        return related[0], related[1:]
    return html_part, []


class TestCidRoundTrip(unittest.TestCase):
    def test_every_cid_has_an_attachment_and_vice_versa(self):
        message = report.build_message(busy_data(), "s@x", "r@x")
        html_part, attachments = parts_of(message)
        body = html_part.get_content()
        referenced = cids_referenced(body)
        attached = {part["Content-ID"].strip("<>") for part in attachments}
        self.assertEqual(
            referenced,
            attached,
            "a cid: reference without its image renders as a broken icon; "
            "an attachment nothing references is dead weight",
        )


class TestEmptyWeek(unittest.TestCase):
    def test_no_data_still_builds_a_letter_with_an_overview(self):
        message = report.build_message(empty_data(), "s@x", "r@x")
        html_part, attachments = parts_of(message)
        body = html_part.get_content()
        self.assertIn("Overview", body)
        self.assertEqual(cids_referenced(body), set(), "no charts may be referenced")
        self.assertEqual(attachments, [], "no charts may be attached")
        self.assertIn("Weekly VPN report", message["Subject"])
        self.assertFalse(message["Subject"].startswith("[!]"))

    def test_text_alternative_exists_first(self):
        message = report.build_message(empty_data(), "s@x", "r@x")
        first = message.get_payload()[0]
        self.assertEqual(first.get_content_type(), "text/plain")


class TestHtmlDiscipline(unittest.TestCase):
    def test_no_pre_no_style_block(self):
        # Monospace blocks reflow badly on phones, and a <style> block is
        # stripped by enough clients that anything in it silently vanishes
        body = parts_of(report.build_message(busy_data(), "s@x", "r@x"))[0].get_content()
        self.assertNotIn("<pre", body)
        self.assertNotIn("<style", body)

    def test_labels_are_escaped(self):
        body = parts_of(report.build_message(busy_data(), "s@x", "r@x"))[0].get_content()
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn(html.escape("<script>alert(1)</script>"), body)

    def test_cyrillic_survives_the_8bit_path(self):
        message = report.build_message(busy_data(), "s@x", "r@x")
        self.assertIn("Тест-инбаунд".encode(), message.as_bytes())


class TestAlerts(unittest.TestCase):
    def test_alerts_prefix_the_subject_and_render(self):
        message = report.build_message(busy_data(), "s@x", "r@x")
        self.assertTrue(message["Subject"].startswith("[!] "))
        self.assertIn("Needs attention", parts_of(message)[0].get_content())

    def test_an_unreachable_node_is_said_not_smoothed_over(self):
        data = empty_data()
        data["unreachable"] = [("ru-msk-1", "no answer")]
        alerts = report.collect_alerts(data)
        self.assertTrue(any("ru-msk-1" in alert for alert in alerts))


class TestMasking(unittest.TestCase):
    def test_a_label_degrades_to_a_stub_not_to_nothing(self):
        masked = report.mask_label("Artemiy")
        self.assertNotEqual(masked, "Artemiy")
        self.assertTrue(masked.startswith("Art"))

    def test_short_labels_reveal_nothing(self):
        self.assertEqual(report.mask_label("Jo"), "**")

    def test_different_labels_stay_different(self):
        self.assertNotEqual(report.mask_label("Dad"), report.mask_label("Mom"))


class TestCounters(unittest.TestCase):
    def test_a_reset_counter_becomes_the_new_absolute_not_a_negative_week(self):
        self.assertEqual(report.clamped_delta(5, 100), 5)
        self.assertEqual(report.clamped_delta(100, 5), 95)

    def test_week_delta_survives_a_mid_week_reset(self):
        export = {"samples": [
            [1, "f2b_banned_total", "sshd", 10],
            [2, "f2b_banned_total", "sshd", 14],
            [3, "f2b_banned_total", "sshd", 2],
            [4, "f2b_banned_total", "sshd", 3],
        ]}
        self.assertEqual(report.counter_week_delta(export, "f2b_banned_total", "sshd"), 7)


class TestWindow(unittest.TestCase):
    def test_the_window_ends_on_the_configured_weekday_and_hour(self):
        now = dt.datetime(2026, 9, 2, 15, tzinfo=ZONE)  # a Wednesday
        start_us, end_us = report.report_window(now, "Europe/Moscow", 9, 0)
        end = dt.datetime.fromtimestamp(end_us / 1_000_000, dt.UTC).astimezone(ZONE)
        self.assertEqual((end.weekday(), end.hour), (0, 9))
        self.assertEqual(end_us - start_us, 7 * 86400 * 1_000_000)

    def test_monday_before_the_hour_reports_the_previous_week(self):
        now = dt.datetime(2026, 8, 31, 8, tzinfo=ZONE)  # Monday, 08:00
        _, end_us = report.report_window(now, "Europe/Moscow", 9, 0)
        end = dt.datetime.fromtimestamp(end_us / 1_000_000, dt.UTC).astimezone(ZONE)
        self.assertEqual(end.date(), dt.date(2026, 8, 24))


class TestSnapshotDiff(unittest.TestCase):
    def test_identical_snapshots_report_nothing(self):
        structure = {"inbounds": [{"key": "0/vless/443", "remark": "SE-exit",
                                   "enable": True, "clients": ["Art****"]}],
                     "routing": []}
        self.assertEqual(report.structure_diff(structure, structure), [])

    def test_changes_are_named(self):
        before = {"inbounds": [{"key": "0/vless/443", "remark": "SE-exit",
                                "enable": True, "clients": ["Art****"]}],
                  "routing": [{"outboundTag": "direct"}]}
        after = {"inbounds": [{"key": "0/vless/443", "remark": "SE-exit",
                               "enable": False, "clients": ["Art****", "Mo*"]},
                              {"key": "0/trojan/8443", "remark": "new-door",
                               "enable": True, "clients": []}],
                 "routing": []}
        lines = report.structure_diff(before, after)
        self.assertTrue(any("new-door" in line for line in lines))
        self.assertTrue(any("disabled" in line for line in lines))
        self.assertTrue(any("Mo*" in line for line in lines))
        self.assertTrue(any("routing" in line for line in lines))

    def test_sanitised_inbound_carries_no_secret(self):
        inbound = {
            "nodeId": 0, "protocol": "vless", "port": 443, "remark": "SE-exit",
            "enable": True,
            "settings": '{"clients": [{"id": "11111111-2222-3333-4444-555555555555", '
                        '"email": "Grandmother", "subId": "abcdef"}]}',
            "clientStats": [{"email": "Grandmother", "up": 1, "down": 2}],
        }
        sanitised = report.sanitise_inbound(inbound)
        flat = str(sanitised)
        self.assertNotIn("11111111", flat)
        self.assertNotIn("abcdef", flat)
        self.assertNotIn("Grandmother", flat)
        self.assertIn("Gra", flat.replace("Grandmother", ""))


class TestPalette(unittest.TestCase):
    def test_theme_names_fill_semantic_slots_and_the_cycle_keeps_its_order(self):
        named = {"paper": "#FFFFFF", "ink": "#222222", "jacket": "#B59CA1",
                 "ash": "#DADADA", "blush": "#FFBDE1", "bow": "#CC0C29",
                 "plum": "#BB5599", "monikaEye": "#76C332", "rule": "#6868B4",
                 "yuri": "#6C4681"}
        palette = report.load_palette(named)
        self.assertEqual(palette["warn"], "#CC0C29")
        # The order is a deuteranopia guarantee, not a taste — see the theme
        self.assertEqual(palette["cycle"],
                         ["#BB5599", "#CC0C29", "#6868B4", "#76C332", "#6C4681"])

    def test_an_unthemed_machine_still_renders(self):
        palette = report.load_palette({})
        self.assertEqual(palette["ink"], report.PALETTE_DEFAULTS["ink"])
        self.assertEqual(len(palette["cycle"]), 5)


class TestTrafficSeries(unittest.TestCase):
    def test_daily_deltas_clamp_a_counter_reset(self):
        day = dt.date(2026, 8, 24)
        snapshots = {
            day: {"traffic": {"inbounds": {"a": {"remark": "SE", "up": 100, "down": 100}},
                              "clients": {}}},
            day + dt.timedelta(days=1): {
                "traffic": {"inbounds": {"a": {"remark": "SE", "up": 10, "down": 5}},
                            "clients": {}}},
        }
        series = report.daily_inbound_series(snapshots)
        self.assertEqual(series[0][1], {"SE": 15}, "a reset must not yield a negative day")


if __name__ == "__main__":
    unittest.main(verbosity=2)
