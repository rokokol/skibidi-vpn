#!/usr/bin/env python3
"""The master's reporter: what only the panel knows.

Everything here reads the panel's own database, opened read-only. Two
commands:

  traffic    write the panel's traffic as a file the collector adds to its own
             push to the station
  problems   print the open items the panel shows, one per line

The reporter mails nothing and pushes nothing itself. The collector is the one
writer of this host's push group, so a series that went away goes away from the
station too. The open items reach the owner in the daily check, which runs
`problems` on the master; the rules are in skibidi_problems.py and nowhere else.

No API and no token: the master holds the panel's database, and reading it is
a file permission rather than a credential. The panel's CLI can only mint a
token by rotating the one it owns, which would knock out whoever else held it;
the database asks nothing of anyone. The columns read here (inbounds,
client_traffics, nodes) are the ones the panel has carried since its first
releases, and a release that moves one fails the deploy-time rehearsal, not a
morning.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import socket
import sqlite3
import sys
import tempfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover — Ubuntu 24.04 ships 3.12
    tomllib = None

sys.path.insert(0, os.environ.get("SKIBIDI_LIB", "/usr/local/lib/skibidi"))
import skibidi_problems  # noqa: E402
import skibidi_push  # noqa: E402


def load_config(path: str | None = None) -> dict:
    file = Path(path or os.environ.get("SKIBIDI_REPORT_CONFIG", "/etc/skibidi/report.toml"))
    with file.open("rb") as handle:
        config = tomllib.load(handle)
    config.setdefault("panel", {})
    config["panel"].setdefault("db", "/etc/x-ui/x-ui.db")
    return config


def client_label(value) -> str:
    """The label as the panel carries it. The dashboard and the daily list are
    the fleet owner's own, and masking their family's names from them would
    protect nobody. What stays out of every push and every list is the
    credential half: UUIDs, subscription ids, keys."""
    return str(value or "")


# ---------------------------------------------------------------- panel database


class PanelError(Exception):
    pass


def open_panel_db(path: str) -> sqlite3.Connection:
    """The panel's database, opened so that this process cannot write it.

    mode=ro refuses every write below SQL level and never creates a missing
    file, so a bug here cannot damage what the panel owns, and a master with
    no panel reads as an error rather than as an empty fleet.
    """
    if not Path(path).is_file():
        raise PanelError(f"no panel database at {path}")
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30)
    connection.execute("PRAGMA query_only = ON")
    connection.row_factory = sqlite3.Row
    return connection


def db_inbounds(connection: sqlite3.Connection) -> list[dict]:
    """Inbounds shaped the way the API served them, so everything downstream —
    the traffic totals, the client questions — reads one shape. A panel
    release that renames a column fails here, in one place, and the
    deploy-time rehearsal is where it fails."""
    inbounds = []
    rows = connection.execute(
        "SELECT id, up, down, remark, enable, port, protocol, node_id FROM inbounds"
    ).fetchall()
    for row in rows:
        stats = connection.execute(
            "SELECT email, up, down, total, expiry_time, enable, last_online "
            "FROM client_traffics WHERE inbound_id = ?",
            (row["id"],),
        ).fetchall()
        inbounds.append({
            "id": row["id"],
            "up": row["up"],
            "down": row["down"],
            "remark": row["remark"],
            "enable": bool(row["enable"]),
            "port": row["port"],
            "protocol": row["protocol"],
            "nodeId": row["node_id"],
            "clientStats": [
                {
                    "email": stat["email"],
                    "up": stat["up"],
                    "down": stat["down"],
                    "total": stat["total"],
                    "expiryTime": stat["expiry_time"],
                    "enable": bool(stat["enable"]),
                    "lastOnline": stat["last_online"],
                }
                for stat in stats
            ],
        })
    return inbounds


def db_nodes(connection: sqlite3.Connection) -> list[dict]:
    """The fleet as the master last heard it: the panel persists each node's
    heartbeat and state beside its address, so the view of the nodes needs no
    token either. A panel without node mode has no table, which is an empty
    fleet rather than an error."""
    try:
        rows = connection.execute("SELECT name, remark, status FROM nodes").fetchall()
    except sqlite3.OperationalError:
        return []
    return [dict(row) for row in rows]


def client_traffic(client: dict) -> tuple[int, int, int]:
    """up, down, lastOnline of a client row as db_inbounds shapes it."""
    return (
        int(client.get("up") or 0),
        int(client.get("down") or 0),
        int(client.get("lastOnline") or 0),
    )


# ---------------------------------------------------------------- traffic


def db_node_names(connection: sqlite3.Connection) -> dict:
    """The name of each node the panel drives, by the id its inbounds carry"""
    try:
        rows = connection.execute("SELECT id, name FROM nodes").fetchall()
    except sqlite3.OperationalError:
        return {}
    return {row["id"]: row["name"] for row in rows}


def panel_traffic(inbounds: list[dict], node_names: dict, own_name: str) -> dict:
    """Cumulative bytes per inbound and per client, as the panel counts them.

    An inbound is named by the node it runs on and by its remark. The
    master's own inbounds carry no node in the panel, so they take own_name.
    The panel lets two inbounds on one node share a remark, and their bytes
    add up under it, because the station refuses a repeated label set.
    """
    traffic: dict = {"inbounds": {}, "clients": {}}
    for inbound in inbounds:
        node_id = inbound.get("nodeId")
        node = own_name if node_id is None else str(node_names.get(node_id, node_id))
        name = str(inbound.get("remark") or "") or f"{inbound.get('protocol')}/{inbound.get('port')}"
        total = traffic["inbounds"].setdefault((node, name), {"up": 0, "down": 0})
        total["up"] += int(inbound.get("up") or 0)
        total["down"] += int(inbound.get("down") or 0)
        for client in inbound.get("clientStats") or []:
            up, down, _last_online = client_traffic(client)
            row = traffic["clients"].setdefault(client_label(client.get("email")), {"up": 0, "down": 0})
            row["up"] += up
            row["down"] += down
    return traffic


def traffic_families(traffic: dict) -> list[dict]:
    families = []
    for name, labels, rows, help_text in (
        ("vpn_inbound_traffic_bytes_total", lambda key: {"node": key[0], "inbound": key[1]},
         traffic["inbounds"], "Bytes an inbound carried, as the panel counts them"),
        ("vpn_client_traffic_bytes_total", lambda key: {"client": key},
         traffic["clients"], "Bytes a client used, as the panel counts them"),
    ):
        samples = [
            ({**labels(key), "direction": direction}, float(row[direction]))
            for key, row in rows.items()
            for direction in ("up", "down")
        ]
        if samples:
            families.append(skibidi_push.family(name, "counter", help_text, samples))
    return families


def traffic(config: dict) -> int:
    """Write the traffic where the collector looks for it. A panel that has
    counted nothing, or that does not answer, leaves no file: the collector
    reads a file as current, and an old one would keep the last numbers on the
    dashboard for as long as the panel stays dead"""
    target = os.environ.get("SKIBIDI_PUSH_TEXTFILE")
    if not target:
        print("this node names no backup station, so there is nowhere to write")
        return 0
    path = Path(target)
    try:
        connection = open_panel_db(config["panel"]["db"])
        try:
            own_name = os.environ.get("SKIBIDI_NODE_NAME") or socket.gethostname()
            families = traffic_families(
                panel_traffic(db_inbounds(connection), db_node_names(connection), own_name)
            )
        finally:
            connection.close()
    except (PanelError, sqlite3.Error) as error:
        path.unlink(missing_ok=True)
        print(f"traffic: {error}", file=sys.stderr)
        return 1
    if not families:
        path.unlink(missing_ok=True)
        return 0
    # Renamed into place, so the collector never reads half a file
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, prefix=".traffic-", delete=False) as handle:
        handle.write(skibidi_push.render(families))
    os.chmod(handle.name, 0o600)
    os.replace(handle.name, path)
    return 0


# ---------------------------------------------------------------- panel live


def gather_panel(config: dict, now_us: int) -> dict:
    """The fleet as the panel sees it now, in the shape the rules in
    skibidi_problems.py read: which nodes are online, and how close each
    client is to its traffic limit and its expiry."""
    connection = open_panel_db(config["panel"]["db"])
    data = {"nodes": [], "clients": []}
    for node in db_nodes(connection):
        data["nodes"].append({
            "name": str(node.get("name") or node.get("remark") or ""),
            "online": node.get("status") == "online",
        })
    now_ms = now_us // 1000
    for inbound in db_inbounds(connection):
        for client in inbound.get("clientStats") or []:
            up, down, _last_online = client_traffic(client)
            total_cap = int(client.get("total") or 0)
            expiry_ms = int(client.get("expiryTime") or 0)
            data["clients"].append({
                "label": client_label(client.get("email")),
                "enable": bool(client.get("enable", True)),
                "cap_share": (up + down) / total_cap if total_cap else None,
                "expires_days": (expiry_ms - now_ms) / 86400000 if expiry_ms > 0 else None,
            })
    connection.close()
    return data


def problems(config: dict) -> int:
    try:
        panel, error = gather_panel(config, int(dt.datetime.now(dt.UTC).timestamp() * 1_000_000)), None
    except (PanelError, sqlite3.Error, json.JSONDecodeError, OSError) as failure:
        panel, error = None, str(failure)
    for line in skibidi_problems.panel_problems(panel, error):
        print(line)
    return 0


def main(argv: list[str], config: dict | None = None) -> int:
    commands = {"traffic": traffic, "problems": problems}
    if argv[:1] and argv[0] in commands:
        return commands[argv[0]](config or load_config())
    print("usage: skibidi-report traffic | problems", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
