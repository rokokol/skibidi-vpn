"""Read panel state without a second writer for the node's push group"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import stat
import sys
from typing import TypeGuard, cast
from urllib.parse import urlsplit

import skibidi_push

MAX_BODY = 1 << 20
MAX_ONLINE_AGE = 10


class PanelError(Exception):
    pass


def local_address(host):
    address = ipaddress.ip_address(host)
    if address.is_loopback:
        return True
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    # UDP connect selects a route without a packet; only this host's own address may use HTTP
    with socket.socket(family, socket.SOCK_DGRAM) as probe:
        probe.connect((host, 9))
        return ipaddress.ip_address(probe.getsockname()[0]) == address


def read_config(path):
    with open(path) as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
            raise PanelError("config permissions")
        config = json.load(handle)
    if not isinstance(config, dict):
        raise PanelError("config shape")
    url = urlsplit(config.get("url", ""))
    if not url.hostname or url.username or url.password or url.query or url.fragment:
        raise PanelError("config URL")
    if url.scheme == "http":
        try:
            if not local_address(url.hostname):
                raise PanelError("cleartext remote URL")
        except ValueError:
            raise PanelError("cleartext remote URL") from None
    elif url.scheme != "https":
        raise PanelError("config scheme")
    bearer = config.get("token")
    if not isinstance(bearer, str) or not bearer or any(c.isspace() for c in bearer):
        raise PanelError("config token")
    pin = config.get("pin_sha256", "").lower().replace(":", "")
    if pin and not re.fullmatch(r"[0-9a-f]{64}", pin):
        raise PanelError("config certificate pin")
    return url, bearer, pin


def api_get(settings, route):
    url, token, pin = settings
    if url.scheme == "https":
        context = ssl._create_unverified_context() if pin else ssl.create_default_context()
        connection = http.client.HTTPSConnection(url.hostname, url.port, timeout=5, context=context)
    else:
        connection = http.client.HTTPConnection(url.hostname, url.port, timeout=5)
    try:
        connection.connect()
        if pin:
            certificate = cast(ssl.SSLSocket, connection.sock).getpeercert(binary_form=True)
            if not certificate or not hmac.compare_digest(hashlib.sha256(certificate).hexdigest(), pin):
                raise PanelError("certificate pin mismatch")
        connection.request("GET", url.path.rstrip("/") + "/panel/api/" + route, headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        })
        response = connection.getresponse()
        if response.status != 200:
            raise PanelError(f"HTTP {response.status}")
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise PanelError("response too large")
        payload = json.loads(body)
        if not isinstance(payload, dict) or payload.get("success") is not True or "obj" not in payload:
            raise PanelError("response envelope")
        return payload["obj"]
    finally:
        connection.close()


def number(value) -> TypeGuard[int | float]:
    return type(value) in (int, float) and math.isfinite(value)


def online_value(history, now):
    if not isinstance(history, list) or not history:
        raise PanelError("empty online history")
    sample = history[-1]
    if not isinstance(sample, dict):
        raise PanelError("online sample shape")
    stamp, value = sample.get("t"), sample.get("v")
    if not number(stamp) or not -2 <= now - stamp <= MAX_ONLINE_AGE:
        raise PanelError("stale online sample")
    if not number(value) or value < 0:
        raise PanelError("online sample value")
    return value


def gauge(name, help_text, value):
    return skibidi_push.family(name, "gauge", help_text, [({}, value)])


def families(environ, now):
    path = environ.get("SKIBIDI_PANEL_CONFIG")
    if not path:
        return []
    up = gauge("x_ui_panel_up", "1 when the panel status API answers with valid state", 0)
    result = [up]
    try:
        settings = read_config(path)
        status = api_get(settings, "server/status")
        state = status.get("xray", {}).get("state") if isinstance(status, dict) else None
        if state not in ("running", "stop", "error"):
            raise PanelError("unknown Xray state")
    except (OSError, ValueError, TypeError, AttributeError, http.client.HTTPException, PanelError) as error:
        print(f"push: panel status unavailable ({type(error).__name__})", file=sys.stderr)
        return result
    result[0] = gauge("x_ui_panel_up", up["help"], 1)
    result.append(gauge("x_ui_xray_up", "1 when the panel reports its local Xray as running", int(state == "running")))
    try:
        value = online_value(api_get(settings, "server/history/online/2"), now)
    except (OSError, ValueError, TypeError, AttributeError, http.client.HTTPException, PanelError) as error:
        print(f"push: panel online unavailable ({type(error).__name__})", file=sys.stderr)
    else:
        result.append(gauge("x_ui_online_clients", "Online clients of this panel and its child nodes without duplicates", value))
    return result
