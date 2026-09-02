#!/usr/bin/env python3
"""Dynamic inventory over a folder of node files — one file per node.

The same folder is read by the 3x-ui-admin-skill, which is why the format is TOML
rather than an Ansible inventory file: one registry, two consumers. Point both at
it with SKIBIDI_NODES_DIR (here) and XUI_NODES_DIR (there).

Groups come from each node's own `capabilities` list, so a role is selected by
what a node declares itself to be, never by matching its name.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tomllib
from pathlib import Path

DEFAULT_DIR = Path(__file__).resolve().parent / "nodes"

# Carried into Ansible; everything else in a node file belongs to other consumers
ANSIBLE_KEYS = {
    "ansible_host",
    "ansible_user",
    "ansible_port",
    "ansible_become",
    "ansible_python_interpreter",
}

# Fields the other consumer needs and Ansible does not. Kept out of hostvars
# because `ansible-inventory --list` prints them, and that output gets pasted
# into issues and chat logs. The panel URL is in the set for its base path,
# which is the one thing hiding the panel from a scan of the tunnel; the
# roles read xui_listen_ip, xui_panel_port and xui_base_path instead
SECRET_KEYS = {"token", "token_file", "panel"}

# Anything shaped like a credential is dropped too, whatever its name. Secrets
# for the roles travel in a vault file passed with -e, never in a node file,
# but a key that lands here by mistake must not reach the printed output
SECRET_SHAPES = ("_key", "_token", "password", "secret")

# Names the inventory itself hands out; a capability spelled like one would
# overwrite the group every role hangs on
RESERVED_GROUPS = {"all", "ungrouped", "nodes"}


def is_secret(key: str) -> bool:
    return key in SECRET_KEYS or any(shape in key.lower() for shape in SECRET_SHAPES)


class InventoryError(Exception):
    pass


def nodes_dir() -> Path:
    return Path(os.environ.get("SKIBIDI_NODES_DIR", DEFAULT_DIR))


def _load_one(path: Path) -> dict:
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise InventoryError(f"{path} is group/other accessible; run: chmod 600 {path}")
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise InventoryError(f"{path}: {exc}") from None


def build(directory: Path) -> dict:
    inventory: dict = {"_meta": {"hostvars": {}}, "all": {"children": ["nodes", "ungrouped"]}}
    nodes: list[str] = []

    for path in sorted(directory.glob("*.toml")):
        name = path.stem
        raw = _load_one(path)

        if "ansible_host" not in raw:
            raise InventoryError(f"{path}: needs ansible_host")

        nodes.append(name)
        inventory["_meta"]["hostvars"][name] = {
            k: v
            for k, v in raw.items()
            if not is_secret(k) and (k in ANSIBLE_KEYS or not k.startswith("ansible_"))
        }

        for capability in raw.get("capabilities", []):
            group = str(capability)
            if group in RESERVED_GROUPS:
                raise InventoryError(f"{path}: capability {group!r} is a name the inventory reserves")
            inventory.setdefault(group, {"hosts": []})["hosts"].append(name)

    inventory["nodes"] = {"hosts": nodes}
    return inventory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--host")
    args = parser.parse_args(argv)

    directory = nodes_dir()
    if not directory.is_dir():
        print(f"no node directory at {directory}", file=sys.stderr)
        return 1

    try:
        inventory = build(directory)
    except InventoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.host:
        print(json.dumps(inventory["_meta"]["hostvars"].get(args.host, {}), indent=2))
    else:
        print(json.dumps(inventory, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
