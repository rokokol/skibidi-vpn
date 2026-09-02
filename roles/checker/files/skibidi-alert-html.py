#!/usr/bin/env python3
"""Render a check failure as a themed letter instead of a wall of journal text.

Reads the journal body on stdin and writes a complete RFC822 message to
stdout, for `sendmail -t`. The plain-text alternative is the raw body,
untouched — a client without HTML loses nothing, and the caller falls back to
mailing that same text if this script fails for any reason at all: prettiness
must never cost an alert.

Colours come from the theme's report stylesheet where the deploy delivered
one, and from a neutral fallback where it did not. Interactivity in mail is
what <details> can carry and no more — scripts do not run in mail clients,
so the full journal folds rather than reacts.
"""

from __future__ import annotations

import argparse
import html
import os
import re
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

THEME_ROLES = {
    "paper": "--ddlc-ground",
    "ink": "--ddlc-ink",
    "muted": "--ddlc-muted",
    "ash": "--ddlc-grid",
    "blush": "--ddlc-code-ground",
    "divider": "--ddlc-divider",
    "warn": "--ddlc-series-2",
    "accent": "--ddlc-accent",
    "ok": "--ddlc-series-4",
}


def parse_theme_css(text: str) -> dict:
    # Only the first :root block — the light one. Mail renders on white, and
    # the dark half of the stylesheet deliberately collapses two series
    root = re.search(r":root\s*\{([^}]*)\}", text)
    if not root:
        return {}
    return dict(re.findall(r"(--[\w-]+)\s*:\s*([^;\s]+)\s*;", root.group(1)))


def load_palette(css_path: str) -> dict:
    try:
        named = parse_theme_css(Path(css_path).read_text())
    except OSError:
        named = {}
    palette = dict(PALETTE_DEFAULTS)
    for slot, variable in THEME_ROLES.items():
        if variable in named:
            palette[slot] = named[variable]
    # The failure box is the game's own inform dialog, and the stylesheet
    # names its colours; a machine nobody themed gets the code ground with
    # the warn colour as its frame
    palette["inform_bg"] = named.get("--ddlc-inform-ground", palette["blush"])
    palette["inform_border"] = named.get("--ddlc-inform-border", palette["warn"])
    return palette


def classify(line: str) -> str:
    if line.startswith("FAIL"):
        return "fail"
    if line.startswith("ok") and "note:" in line:
        return "note"
    if line.startswith("ok"):
        return "ok"
    return "meta"


# The system's own pairing: Doki (the game's face) for headings and prose,
# DepartureMono for data — mail clients load no web fonts, so the letter names
# the faces installed on the reader's machines and degrades to honest stacks
FONT_PROSE = "Doki, Spectral, Georgia, 'Times New Roman', serif"
FONT_MONO = ("'DepartureMono Nerd Font Mono', 'DepartureMono Nerd Font', "
             "'Departure Mono', ui-monospace, 'SF Mono', Menlo, monospace")


def render_html(body: str, unit: str, host: str, palette: dict) -> str:
    """The theme's report stylesheet, spelled as inline styles: prose on the
    ground colour, the heading underlined by the divider, the failures as the
    game's inform dialog, and the journal on the code ground it belongs to."""
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
            return (f'<div style="padding:2px 0;color:{palette["warn"]}">'
                    f"✗ {text}</div>")
        if kind == "note":
            return (f'<div style="padding:2px 0;color:{palette["ink"]}">'
                    f'<span style="color:{palette["accent"]}">○</span> {text}</div>')
        if kind == "ok":
            return (f'<div style="padding:2px 0;color:{palette["ink"]}">'
                    f'<span style="color:{palette["ok"]}">✓</span> {text}</div>')
        return f'<div style="padding:2px 0;color:{palette["ink"]}">{text}</div>'

    sections = []
    if fails:
        items = "".join(f"<li>{html.escape(line[4:].strip())}</li>" for line in fails)
        # The game's own dialog box: a pink ground framed on all sides,
        # everything centred, the ink doing the talking
        sections.append(
            f'<div style="background:{palette["inform_bg"]};border:2px solid '
            f'{palette["inform_border"]};border-radius:6px;'
            f'padding:20px 24px;margin:18px 0;color:{palette["ink"]};text-align:center">'
            '<div style="font-size:17px;font-weight:normal">Failed</div>'
            f'<ul style="margin:8px 0 0;padding:0;list-style:none;font-size:14px;'
            f'line-height:1.6">{items}</ul></div>'
        )
    # The whole run folds away rather than scrolling forever; <details> is the
    # one fold mail clients honour, and the ones that do not simply show it
    # open. The journal sits on the code ground, where machine text lives
    sections.append(
        '<details style="margin:16px 0">'
        f'<summary style="font-size:16px;color:{palette["ink"]};'
        'font-weight:normal;cursor:pointer">Every check from this run</summary>'
        f'<div style="background:{palette["blush"]};border-radius:4px;'
        f'padding:12px 16px;margin-top:8px;font-family:{FONT_MONO};font-size:12px">'
        f'{"".join(row(line) for line in lines)}</div></details>'
    )
    return (
        f'<div style="background:{palette["paper"]};color:{palette["ink"]};'
        f'font-family:{FONT_PROSE};line-height:1.55;padding:28px 20px 48px">'
        f'<div style="max-width:736px;margin:0 auto">'
        f'<h1 style="font-size:27px;line-height:1.25;font-weight:normal;'
        f'color:{palette["ink"]};margin:0;'
        f'border-bottom:2px solid {palette["divider"]};padding-bottom:6px">'
        f"{html.escape(unit)} failed</h1>"
        f'<p style="margin:2px 0 10px;font-size:13px;color:{palette["muted"]}">'
        f"on {html.escape(host)}</p>" + "".join(sections) + "</div></div>"
    )


def build_message(body: str, unit: str, host: str, subject: str,
                  to: str, sender: str, css_path: str) -> EmailMessage:
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
        render_html(body, unit, host, load_palette(css_path)),
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
    parser.add_argument("--css", default=os.environ.get(
        "SKIBIDI_REPORT_CSS_FILE", "/etc/skibidi/ddlc-report.css"))
    arguments = parser.parse_args()

    message = build_message(
        sys.stdin.read(), arguments.unit, arguments.host,
        arguments.subject, arguments.to, arguments.sender, arguments.css,
    )
    sys.stdout.buffer.write(message.as_bytes())
    return 0


if __name__ == "__main__":
    sys.exit(main())
