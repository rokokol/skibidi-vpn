# CLAUDE.md

Ansible roles for 3x-ui nodes on Ubuntu. The **roles are public and generic**; the fleet is not. Never let a real address, hostname, Reality donor or token into a tracked file — those live in the private node registry, which this repository only reads.

## The boundary that decides where a change goes

Anything inside `/etc/x-ui/x-ui.db` — inbounds, clients, routing, panel settings — belongs to the `xui-admin` skill and is covered by the database backup. This repository owns the OS layer around it. A change that could be made through the panel API does not belong here.

Across repositories the same rule holds and is not negotiable: **a single source of truth is a property, not a copy.** The mail host declares which nodes may use its alert intake; this repository holds no copy of that list and instead probes that the intake answers. Do not add a shared inventory file, and do not add a CI job that needs both repositories.

## The registry

One TOML file per node in `$SKIBIDI_NODES_DIR` (default `inventory/nodes/`, git-ignored). `inventory/nodes.py` turns each node's `capabilities` list into Ansible groups, so a role is chosen by what a node declares itself to be — never by matching its name. The same directory is read by the `xui-admin` skill via `XUI_NODES_DIR`; that is why it is TOML rather than an Ansible inventory file.

The inventory strips `token` and `token_file` from host variables. Keep it that way: `ansible-inventory --list` output ends up pasted into issues.

## Build and check

```sh
nix develop
ansible-playbook site.yml --syntax-check
ansible-lint                 # must stay green at the production profile
./tests/no-secrets.sh
nix flake check
molecule test                # real Ubuntu VM under KVM
```

⚠️ **`.gitignore` patterns here are deliberately narrow.** A blanket `*secret*` once matched `tests/no-secrets.sh`, so the guard against leaking secrets was itself untracked — and only `nix flake check` noticed, because the file it wanted was missing from the flake source. Widen a pattern only after checking what else it swallows.

⚠️ **A check that cannot go red is not evidence.** `tests/no-secrets.sh` was proven by planting a private key and a literal token and watching it fail. Do the same for anything new: break the thing it watches, run it, then restore.

## Writing tasks

- Every mutating task states the failure it prevents, not what the command does. If a comment restates the module below it, delete it
- A task that restarts the panel must be detached from the SSH session, because restarting it drops the tunnel the session may be riding
- Back up `/etc/x-ui/x-ui.db` before touching anything the panel owns, and keep the rollback on the node
- Assert the result rather than trusting the module: the `xui` role proves with `ss` that the panel listens only on the tunnel address, because a panel on a public address exposes every client secret
- Never print a full inbound or the Xray template — they carry client UUIDs, subscription ids and Reality private keys

## Releases

Every user-visible change gets a line under `## [Unreleased]` in `CHANGELOG.md`; a release moves them under a version, tags `v<x.y.z>` and cuts a `gh release`.
