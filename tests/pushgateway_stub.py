#!/usr/bin/env python3
"""A Pushgateway that checks what the real one and the station's nginx check.

The unit tests start it in a thread on loopback. The molecule scenario runs it
as a service on the stand-in station address, so a node pushes to something
that refuses what the station refuses: any path but one group, any user but
the group's own instance, a body the exposition parser rejects, a name outside
the `vpn_` prefix. Every request, accepted or refused, is kept for the test to
read back. Passwords are never kept.

    pushgateway_stub.py --listen ADDRESS:PORT --user NAME --password-file FILE --log FILE
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

NAME = r"[a-zA-Z_:][a-zA-Z0-9_:]*"
SAMPLE = re.compile(
    rf"^(?P<name>{NAME})(?:\{{(?P<labels>.*)\}})? (?P<value>[-+]?(?:[0-9.]+(?:[eE][-+]?[0-9]+)?|Inf|NaN))$"
)
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"(?:,|$)')
KINDS = {"counter", "gauge", "untyped"}


class Refused(Exception):
    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def parse_exposition(text: str, prefix: str = "vpn_") -> dict:
    """The families of a text exposition, or Refused(400) for what the real
    parser would refuse. Returns {name: {"type", "help", "samples": [(labels, value)]}}"""
    if not text.endswith("\n"):
        raise Refused(400, "text format must end with a newline")
    families: dict = {}
    for number, line in enumerate(text.split("\n")[:-1], 1):
        if not line:
            continue
        if line.startswith("# HELP "):
            name, _, help_text = line[7:].partition(" ")
            families.setdefault(name, {"type": None, "help": None, "samples": []})["help"] = help_text
            continue
        if line.startswith("# TYPE "):
            name, _, kind = line[7:].partition(" ")
            if kind not in KINDS:
                raise Refused(400, f"line {number}: unknown type {kind!r}")
            family = families.setdefault(name, {"type": None, "help": None, "samples": []})
            if family["samples"]:
                raise Refused(400, f"line {number}: TYPE after the samples of {name}")
            family["type"] = kind
            continue
        if line.startswith("#"):
            continue
        found = SAMPLE.match(line)
        if not found:
            raise Refused(400, f"line {number}: not a sample")
        name = found["name"]
        if not name.startswith(prefix) and name != "node_problem":
            raise Refused(400, f"line {number}: {name} is outside the {prefix} prefix")
        labels = {}
        rest = found["labels"] or ""
        position = 0
        while position < len(rest):
            label = LABEL.match(rest, position)
            if not label:
                raise Refused(400, f"line {number}: bad labels")
            labels[label[1]] = label[2]
            position = label.end()
        family = families.setdefault(name, {"type": None, "help": None, "samples": []})
        if any(existing == labels for existing, _value in family["samples"]):
            raise Refused(400, f"line {number}: {name} repeats a label set")
        family["samples"].append((labels, float(found["value"])))
    return families


class Stub:
    """The server and the requests it saw."""

    def __init__(self, user: str, password: str, address: str = "127.0.0.1", port: int = 0,
                 log: Path | None = None, job: str = "vpn"):
        self.user = user
        self.login = (user, password)
        self.job = job
        self.requests: list[dict] = []
        self.log = log
        self.lock = threading.Lock()
        self.server = ThreadingHTTPServer((address, port), self.handler())
        self.port = self.server.server_address[1]

    def handler(self):
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_request(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode("utf-8", "replace")
                record = {"method": self.command, "path": self.path, "user": None,
                          "body": body, "status": None, "reason": ""}
                try:
                    stub.check(self.headers.get("Authorization", ""), self.command, self.path,
                               body, record)
                    status = 200
                except Refused as refusal:
                    status, record["reason"] = refusal.status, refusal.reason
                record["status"] = status
                with stub.lock:
                    stub.requests.append(record)
                    if stub.log:
                        with stub.log.open("a") as handle:
                            handle.write(json.dumps(record, sort_keys=True) + "\n")
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_POST = do_PUT = do_GET = do_DELETE = do_request

            def log_message(self, format, *args):  # noqa: A002 — the base class names it
                return

        return Handler

    def check(self, authorization: str, method: str, path: str, body: str, record: dict):
        # The station's nginx: basic auth first, then one path, then no reads
        scheme, _, token = authorization.partition(" ")
        try:
            user, _, password = base64.b64decode(token).decode().partition(":")
        except ValueError:
            user, password = "", ""
        if scheme != "Basic" or (user, password) != self.login:
            raise Refused(401, "credentials refused")
        record["user"] = user
        if method not in ("POST", "PUT"):
            raise Refused(405, "only a push is allowed")
        expected = f"/metrics/job/{self.job}/instance/{user}"
        if urllib.parse.unquote(path) != expected:
            raise Refused(404, f"the one path is {expected}")
        parse_exposition(body)

    def start(self):
        threading.Thread(target=self.server.serve_forever, args=(0.01,), daemon=True).start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--listen", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--log", required=True)
    args = parser.parse_args(argv)
    address, _, port = args.listen.rpartition(":")
    stub = Stub(args.user, Path(args.password_file).read_text(), address, int(port),
                Path(args.log))
    stub.server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
