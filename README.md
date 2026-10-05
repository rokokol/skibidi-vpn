# skibidi-vpn ೖ(⑅σ̑ᴗσ̑)ೖ

[![workarounds](https://img.shields.io/badge/docs-workarounds-555?style=flat)](WORKAROUNDS.md)
[![deviations](https://img.shields.io/badge/docs-deviations-555?style=flat)](DEVIATIONS.md)
[![build](https://github.com/rokokol/skibidi-vpn/actions/workflows/build.yml/badge.svg)](https://github.com/rokokol/skibidi-vpn/actions/workflows/build.yml)
[![molecule](https://github.com/rokokol/skibidi-vpn/actions/workflows/molecule.yml/badge.svg)](https://github.com/rokokol/skibidi-vpn/actions/workflows/molecule.yml)

Ansible roles that build and maintain a 3x-ui VPN node on Ubuntu — the panel, its certificate, the tunnel, the firewall and the periodic checks. The roles are generic; the fleet they are pointed at is not part of this repository

## What this covers, and what it does not

The split follows the database. Everything inside `/etc/x-ui/x-ui.db` — inbounds, clients, routing rules, panel settings — is administered through the panel API by the [3x-ui-admin-skill](https://github.com/rokokol/3x-ui-admin-skill) skill and is covered by the database backup. This repository owns everything outside it: packages, kernel settings, the firewall, the tunnel, nginx, certificates, timers and the backup mechanism itself

Nothing here writes to the panel database except the pre-change backup

## Nodes are files

A node is one TOML file. Adding a node means dropping a file into the registry directory; no list of nodes exists anywhere in this repository, and roles are selected by the capabilities a node declares about itself rather than by matching its name

```toml
ansible_host = "198.51.100.7"
ansible_user = "root"
capabilities = ["master"]
xui_listen_ip = "100.72.0.4"
xui_panel_port = 16099
```

`inventory.example/nodes/example.toml` documents every field. The real registry lives outside this repository — point both consumers at it:

```sh
export SKIBIDI_NODES_DIR=/path/to/private/nodes   # this repo
export XUI_NODES_DIR=/path/to/private/nodes       # the 3x-ui-admin-skill
```

One registry, two consumers. A node file must be `chmod 600`; the inventory refuses to read one that anyone else can open, and strips the panel token — and anything else shaped like a credential — from host variables so it never reaches `ansible-inventory --list` output

## Secrets

The roles need two secrets and the registry holds neither: a Tailscale auth key, read only on a node that has not joined yet, and a Cloudflare token for the DNS-01 challenge. The optional backup below adds two more per node that uses it. They travel in a vault file passed to the play:

```sh
cp vault.example.yml vault.yml          # git-ignored
ansible-vault encrypt vault.yml
ansible-playbook site.yml -e @vault.yml --ask-vault-pass
```

The panel needs no credential from this repository at all: the weekly report reads the panel's database on the master, opened read-only. The panel's API token belongs to the `3x-ui-admin-skill`, issued in the panel's UI under its own name

## Backup

The backup channel is optional and off by default. A node whose file names no backup station gets no restic, no timer, no unit and no secret, and its checks say nothing about a backup; a deploy also removes what an earlier one installed. A fleet without a receiver, or without a tailnet at all, deploys and checks clean

A node that names a station pushes a restic snapshot to it on a timer:

- a copy of the panel's database and of the metric store, each taken with `sqlite3 .backup` into a directory only root can read, and checked for integrity before it leaves
- on the master, the weekly report's state as well

The certificate in `/root/cert` and acme.sh's home `/root/.acme.sh` are not backed up: a rebuilt node issues a new wildcard over DNS-01 with the token from the vault, and a copy would put the wildcard's private key on one more machine. The Tailscale identity is not backed up either: a restored copy would collide with the original node on the tailnet, while a rebuilt node joins again with the auth key

### The receiver

A [rest-server](https://github.com/restic/rest-server) that the node can reach, set up like this:

- one htpasswd account per node, kept to its own repository by `--private-repos`, so the repository path is the account name
- `--append-only`, so a node can add snapshots and never remove one. Nothing on the node prunes; retention is the receiver's business
- plain HTTP only inside the tunnel ranges, where WireGuard already encrypts. Anywhere else the URL must be `https://`, which is accepted wherever the receiver is

The repository is encrypted with a password that the node and the owner know and the receiver does not. Keep a copy of it away from the fleet: no snapshot can be read without it

### Turning it on for one node

In the node's file, the receiver's base URL, and the account when it is not the node's name:

```toml
backup_url = "http://<station address>:<port>"
# backup_user = "<account on the station>"
```

In `vault.yml`, one entry under the node's name:

```yaml
backup_secrets:
  <node name>:
    rest_password: <the node's password on the station>
    repository_password: <the restic repository password>
```

The next deploy installs the pinned restic and the timer, creates the repository unless it already exists, and pushes the first snapshot. A deploy fails before restic, the secrets or the timer arrive when the vault has no entry for the node, or when the URL is `http://` outside the tunnel. To leave the channel off, set nothing: the vault entry is read only for a node with `backup_url`. To turn it off again, remove `backup_url` and deploy. Restoring is restic's own `restore` against the same repository, with the same two passwords

### What the checker watches

Only on a node with `backup_url`: the timer is enabled and has fired within its interval, the station still passes the HTTP rule above, and the secrets and the staged copies stay readable by root alone. A failed push raises the same alert as any other failed unit

## Use

```sh
nix develop                       # ansible, ansible-lint, molecule, qemu
ansible-inventory --graph         # what the registry resolves to
ansible-playbook site.yml --check  # dry run
ansible-playbook site.yml
```

## Checks

```sh
ansible-playbook site.yml --syntax-check
ansible-lint                      # passes at the production profile
./tests/no-secrets.sh             # nothing secret reached a tracked file
./tests/falsify-secrets.sh        # and the gate would notice if one did
nix flake check
```

`molecule test` builds a real Ubuntu VM under KVM and runs the roles against it. A container is not enough here: systemd, the firewall and the tunnel are three of the things worth testing, and none of them behave in one

The molecule workflow is dispatch-only, so its badge shows no status until a run is started by hand: hosted runners provide /dev/kvm inconsistently, and a scheduled red would indict the runner pool rather than the roles

## Roadmap

- The `sub` capability is declared on the master and read by nothing yet. It is reserved for the day subscriptions are served through Clash: the node carrying it will get the subscription port opened to the CDN's ranges alone, with `firewall_tcp_open_from`, and the checker will hold that port to those sources

Everything that reads as a workaround and is not one is in [`DEVIATIONS.md`](DEVIATIONS.md), with the trade behind it; the gaps that force a workaround at all are in [`WORKAROUNDS.md`](WORKAROUNDS.md), with what would retire each

## Roles

| Role | What it owns |
| --- | --- |
| `common` | congestion control, queue discipline, conntrack limits, one outgoing address family, the system resolver |
| `firewall` | ufw policy, the three public ports, and hiding the tunnel's direct path |
| `tailscale` | the private network the panel is reachable on, and Tailscale SSH where a node opts in |
| `xui` | the pinned panel, bound to the tunnel address, asserted afterwards |
| `geodata` | the geo databases Xray routes by, refreshed and checked against the digests their releases publish |
| `certs` | a wildcard certificate over DNS-01, so only the wildcard reaches Certificate Transparency |
| `nginx` | port 80, and the optional egress-address echo |
| `fail2ban` | the sshd, recidive and panel address-limit jails, each proven to read the log it is meant to |
| `metrics` | a ten-minute sampler of what the panel does not know, served read-only on the tailnet by the [metrics API](docs/metrics-api.md) |
| `reporter` | the Monday letter, built from the panel's database and the fleet's metric stores; master only |
| `backup` | the optional push of the panel's database, the metric store and the report's state to a restic receiver the node names; off by default, see [Backup](#backup) |
| `checker` | the half-hourly self-check, mailed on failure straight past the master |
| `warp` | Cloudflare WARP as a local proxy, with a watchdog that counts its own restarts |
