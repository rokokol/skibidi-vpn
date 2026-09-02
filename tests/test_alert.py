"""The alert letter, proven on a synthetic journal — no node, no failure.

The one property everything else defers to: the plain-text alternative is the
raw journal, byte for byte, because the renderer sits in front of an alert
path and must never subtract information a client without HTML would have had.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parent.parent
    / "roles" / "checker" / "files" / "skibidi-alert-html.py"
)
specification = importlib.util.spec_from_file_location("skibidi_alert_html", SCRIPT)
alert = importlib.util.module_from_spec(specification)
sys.modules["skibidi_alert_html"] = alert
specification.loader.exec_module(alert)

BODY = """skibidi-check.service failed on test-node at 2026-09-01T14:48:23+00:00.

ok   x-ui is running
ok   conntrack 1% used (784 of 65536)
FAIL the firewall also allows 9999/tcp, which this node does not declare
FAIL inbound <script>alert(1)</script> is enabled but nothing listens on it
ok   note: udp/8443 listens publicly but the firewall does not admit it
ok   inbound port 443 is served <script>alert(1)</script>
ok   Тест-инбаунд отвечает
1 check(s) failed on test-node
"""

THEME_CSS = ":root { --ddlc-series-2: #CC0C29; --ddlc-ground: #FFFFFF; }"


def build(css_path="/nonexistent/theme.css"):
    import email
    import email.policy

    message = alert.build_message(
        BODY, "skibidi-check.service", "test-node",
        "[test-node] 1 check(s) failed on test-node",
        "vpn@example.org", "skibidi-vpn@test-node", css_path,
    )
    # Through bytes and back, because sendmail sees bytes, not the object
    return email.message_from_bytes(message.as_bytes(), policy=email.policy.default)


def html_part(message):
    return next(part for part in message.walk()
                if part.get_content_type() == "text/html").get_content()


class TestAlertMessage(unittest.TestCase):
    def test_the_text_alternative_is_the_raw_journal(self):
        message = build()
        text = next(part for part in message.walk()
                    if part.get_content_type() == "text/plain").get_content()
        self.assertEqual(text.strip(), BODY.strip())

    def test_headers_mark_it_machine_sent(self):
        message = build()
        self.assertEqual(message["Auto-Submitted"], "auto-generated")
        self.assertEqual(message["To"], "vpn@example.org")
        self.assertIn("failed", message["Subject"])

    def test_the_failure_is_loud_and_the_journal_folds(self):
        body = html_part(build())
        self.assertIn("the firewall also allows 9999/tcp", body)
        self.assertIn("<details", body)
        self.assertNotIn("<pre", body)
        self.assertNotIn("<style", body)

    def test_journal_text_is_escaped(self):
        # The fixture plants the same payload in an ok line and in a FAIL
        # line, because the two travel through different rendering paths —
        # the fold and the Failed box — and each must escape on its own
        body = html_part(build())
        self.assertNotIn("<script>alert(1)</script>", body)

    def test_cyrillic_survives_the_8bit_path(self):
        message = build()
        self.assertIn("Тест-инбаунд".encode(), message.as_bytes())

    def test_theme_colours_apply_when_the_stylesheet_exists(self):
        import tempfile

        css = Path(tempfile.mkdtemp(prefix="skibidi-css-")) / "theme.css"
        css.write_text(THEME_CSS)
        body = html_part(build(css_path=str(css)))
        self.assertIn("#CC0C29", body)

    def test_a_missing_stylesheet_still_renders(self):
        body = html_part(build(css_path="/nonexistent/theme.css"))
        self.assertIn(alert.PALETTE_DEFAULTS["warn"], body)

    def test_the_failed_box_takes_the_inform_colours_from_the_stylesheet(self):
        import tempfile

        css = Path(tempfile.mkdtemp(prefix="skibidi-css-")) / "theme.css"
        css.write_text(":root { --ddlc-inform-ground: #FFDBF0; --ddlc-inform-border: #FFBDE1; }")
        body = html_part(build(css_path=str(css)))
        self.assertIn("#FFDBF0", body)
        self.assertIn("#FFBDE1", body)


class TestClassification(unittest.TestCase):
    def test_the_three_kinds_are_told_apart(self):
        self.assertEqual(alert.classify("FAIL something broke"), "fail")
        self.assertEqual(alert.classify("ok   note: udp/8443 listens"), "note")
        self.assertEqual(alert.classify("ok   x-ui is running"), "ok")
        self.assertEqual(alert.classify("1 check(s) failed"), "meta")


if __name__ == "__main__":
    unittest.main(verbosity=2)
