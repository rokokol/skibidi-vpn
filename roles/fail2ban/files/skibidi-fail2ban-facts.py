#!/usr/bin/env python3
"""Answer what the fail2ban role asks a node before it writes the jails.

`public-address` prints the IPv4 address the internet sees this node at, or
nothing. A node in a cloud that puts it behind NAT has only a private address
on its interface, and the cloud's own metadata service names the public one.

`client-only-bans` prints each address recidive holds that no jail but the
client jails ever banned, one a line. Those are clients who passed the
panel's device limit, not attackers.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

# The GCE-shaped metadata service, which Yandex Cloud and Google Cloud serve.
# It answers on a link-local address inside the cloud only, so asking it
# reaches no third party
METADATA_URL = "http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip"
FAIL2BAN_LOGS = ("/var/log/fail2ban.log.1", "/var/log/fail2ban.log")


# What no other host on the internet can reach this node at: the private
# ranges, the carrier NAT range the tunnel also takes, link-local and loopback
INTERNAL = tuple(ipaddress.IPv4Network(network) for network in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8",
))


def global_address(text: str) -> str | None:
    try:
        address = ipaddress.IPv4Address(text.strip())
    except ValueError:
        return None
    if address.is_unspecified or address.is_multicast or any(address in network for network in INTERNAL):
        return None
    return str(address)


def public_address(route: str, metadata) -> str | None:
    """The source address of the default route when it is public, else what
    the metadata service says, else None"""
    words = route.split()
    if "src" in words[:-1]:
        found = global_address(words[words.index("src") + 1])
        if found:
            return found
    try:
        return global_address(metadata())
    except OSError:
        return None


def ask_metadata() -> str:
    request = urllib.request.Request(METADATA_URL, headers={"Metadata-Flavor": "Google"})
    with urllib.request.urlopen(request, timeout=3) as answer:
        return answer.read(64).decode(errors="replace")


def banned_addresses(status: str) -> list[str]:
    """The addresses `fail2ban-client status JAIL` lists as banned"""
    match = re.search(r"Banned IP list:[ \t]*(.*)", status)
    return match.group(1).split() if match else []


def client_only(banned: list[str], log: str, client_jails: set[str]) -> list[str]:
    """The banned addresses whose every ban in the log came from a client jail
    or from recidive itself. An address with no ban left in the log stays
    banned: lifting an attacker costs more than a client who waits"""
    jails: dict = {}
    for match in re.finditer(r"\[([^]]+)\] Ban (\S+)$", log, re.MULTILINE):
        jails.setdefault(match.group(2), set()).add(match.group(1))
    lifted = []
    for address in banned:
        causes = jails.get(address, set()) - {"recidive"}
        if causes and causes <= client_jails:
            lifted.append(address)
    return lifted


def main(argv: list[str]) -> int:
    if argv == ["public-address"]:
        route = subprocess.run(["ip", "-4", "-o", "route", "get", "1.1.1.1"],
                               capture_output=True, text=True, check=False).stdout
        found = public_address(route, ask_metadata)
        if found:
            print(found)
        return 0
    if len(argv) >= 2 and argv[0] == "client-only-bans":
        status = subprocess.run(["fail2ban-client", "status", "recidive"],
                                capture_output=True, text=True, check=True).stdout
        log = "".join(Path(path).read_text(errors="replace") for path in FAIL2BAN_LOGS if Path(path).exists())
        for address in client_only(banned_addresses(status), log, set(argv[1:])):
            print(address)
        return 0
    print("usage: skibidi-fail2ban-facts public-address | client-only-bans JAIL...", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
