#!/usr/bin/env python3
"""Render a check failure as a themed letter instead of a wall of journal text.

Reads the journal body on stdin and writes a complete RFC822 message to
stdout, for `sendmail -t`. The plain-text alternative is the raw body,
untouched — a client without HTML loses nothing, and the caller falls back to
mailing that same text if this script fails for any reason at all: prettiness
must never cost an alert.

Colours, faces and element styles come from the theme's letter file where
the deploy delivered one, and from a neutral fallback where it did not. Interactivity in mail is
what <details> can carry and no more — scripts do not run in mail clients,
so the full journal folds rather than reacts.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import sys
from email.message import EmailMessage
from pathlib import Path

PALETTE_DEFAULTS = {
    "paper": "#ffffff",
    "ink": "#1f2430",
    "muted": "#5b6472",
    "accent": "#3b6ea5",
    "ok": "#3f7d4e",
    "warn": "#b3423a",
    "ash": "#d8dce3",
    "blush": "#eef1f5",
    "divider": "#c3cbd6",
}

# What each slot here means in the theme's role vocabulary, the contract
# ddlc-themes keeps for letters
THEME_ROLES = {
    "paper": "ground",
    "ink": "text",
    "muted": "muted",
    "ash": "grid",
    "blush": "code-ground",
    "divider": "line",
    "warn": "danger",
    "accent": "accent",
    "ok": "ok",
}


def load_theme(path: str) -> dict:
    """The theme's letter file, literal values only because mail drops var();
    a machine nobody themed has none, and gets an empty theme."""
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}


def load_palette(theme: dict) -> dict:
    colors = theme.get("colors", {})
    palette = dict(PALETTE_DEFAULTS)
    for slot, role in THEME_ROLES.items():
        if role in colors:
            palette[slot] = colors[role]
    return palette


def styler(theme: dict):
    """The theme's style value for an element, with what this element alone
    needs on top; a later declaration in a style attribute wins. Unthemed, an
    element keeps the reader's default look and only the extra"""
    styles = theme.get("styles", {})

    def style(element: str, extra: str = "") -> str:
        return ";".join(part for part in (styles.get(element, ""), extra) if part)

    return style


def classify(line: str) -> str:
    if line.startswith("FAIL"):
        return "fail"
    if line.startswith("ok") and "note:" in line:
        return "note"
    if line.startswith("ok"):
        return "ok"
    return "meta"


def render_html(body: str, unit: str, host: str, theme: dict) -> str:
    """The theme's letter styles: prose on the ground colour, the heading
    underlined by the divider, the failures as the game's "Just Monika."
    pop-up, and the journal on the code ground it belongs to."""
    palette = load_palette(theme)
    style = styler(theme)
    lines = [line for line in body.splitlines() if line.strip()]
    fails = [line for line in lines if classify(line) == "fail"]

    def row(line: str) -> str:
        # Ink on the code ground, always: muted text on pink was unreadable.
        # The level lives in the coloured marker and, for a failure, in weight
        kind = classify(line)
        text = line[4:].strip() if kind in ("ok", "fail", "note") else line
        if kind == "note":
            text = text.removeprefix("note:").strip()
        text = html.escape(text)
        if kind == "fail":
            # The warn ink itself, not a synthetic bold — a pixel face fakes
            # weight badly, and the palette's only red is allowed to shout
            return f'<div style="{style("journal-line", "color:" + palette["warn"])}">✗ {text}</div>'
        if kind == "note":
            return (f'<div style="{style("journal-line")}">'
                    f'<span style="color:{palette["accent"]}">○</span> {text}</div>')
        if kind == "ok":
            return (f'<div style="{style("journal-line")}">'
                    f'<span style="color:{palette["ok"]}">✓</span> {text}</div>')
        return f'<div style="{style("journal-line")}">{text}</div>'

    sections = []
    if fails:
        items = "".join(f'<li style="{style("inform-item")}">{html.escape(line[4:].strip())}</li>'
                        for line in fails)
        # The game's "Just Monika." pop-up: a pale ground in a thick frame,
        # everything centred, the ink doing the talking. Unthemed, the warn
        # colour still frames it, so it never reads as prose
        frame = "" if theme else f'border:2px solid {palette["warn"]};padding:12px'
        sections.append(
            f'<div style="{style("inform", frame)}">'
            f'<div style="{style("inform-title")}">Failed</div>'
            f'<ul style="{style("inform-list")}">{items}</ul></div>'
        )
    # The whole run folds away rather than scrolling forever; <details> is the
    # one fold mail clients honour, and the ones that do not simply show it
    # open. The journal sits on the code ground, where machine text lives
    mono = "" if theme else "font-family:monospace"
    sections.append(
        f'<details style="{style("details")}">'
        f'<summary style="{style("summary")}">Every check from this run</summary>'
        f'<div style="{style("journal", mono)}">'
        f'{"".join(row(line) for line in lines)}</div></details>'
    )
    return (
        f'<div style="{style("page")}">'
        f'<div style="{style("column")}">'
        f'<h1 style="{style("h1")}">{html.escape(unit)} failed</h1>'
        f'<p style="{style("sub")}">on {html.escape(host)}</p>'
        + "".join(sections) + "</div></div>"
    )


def build_message(body: str, unit: str, host: str, subject: str,
                  to: str, sender: str, theme_path: str) -> EmailMessage:
    message = EmailMessage()
    message["To"] = to
    message["From"] = f"skibidi-vpn <{sender}>"
    # The subject arrives computed by the caller from the journal's last line,
    # and stays untouched: that line is the summary the check prints on
    # purpose, and it is what a phone notification shows
    message["Subject"] = subject
    message["Auto-Submitted"] = "auto-generated"
    # Journal lines are arbitrary bytes; utf-8 with 8bit is what keeps a
    # Russian remark from breaking the part
    message.set_content(body, charset="utf-8", cte="8bit")
    message.add_alternative(
        render_html(body, unit, host, load_theme(theme_path)),
        subtype="html", charset="utf-8",
    )
    return message


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--unit", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--to", required=True)
    parser.add_argument("--sender", required=True)
    parser.add_argument("--theme", default=os.environ.get(
        "SKIBIDI_MAIL_FILE", "/etc/skibidi/ddlc-mail.json"))
    arguments = parser.parse_args()

    message = build_message(
        sys.stdin.read(), arguments.unit, arguments.host,
        arguments.subject, arguments.to, arguments.sender, arguments.theme,
    )
    sys.stdout.buffer.write(message.as_bytes())
    return 0


if __name__ == "__main__":
    sys.exit(main())
