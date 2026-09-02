# skibidi-vpn ೖ(⑅σ̑ᴗσ̑)ೖ

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

The roles need two secrets and the registry holds neither: a Tailscale auth key, read only on a node that has not joined yet, and a Cloudflare token for the DNS-01 challenge. They travel in a vault file passed to the play:

```sh
cp vault.example.yml vault.yml          # git-ignored
ansible-vault encrypt vault.yml
ansible-playbook site.yml -e @vault.yml --ask-vault-pass
```

The panel needs no credential from this repository at all: the weekly report reads the panel's database on the master, opened read-only. The panel's API token belongs to the `3x-ui-admin-skill`, issued in the panel's UI under its own name

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

Everything that reads as a workaround and is not one is in [`docs/deviations.md`](docs/deviations.md), with what would retire it

## Roles

| Role | What it owns |
| --- | --- |
| `common` | congestion control, queue discipline, conntrack limits, one outgoing address family |
| `firewall` | ufw policy, the three public ports, and hiding the tunnel's direct path |
| `tailscale` | the private network the panel is reachable on |
| `xui` | the pinned panel, bound to the tunnel address, asserted afterwards |
| `certs` | a wildcard certificate over DNS-01, so only the wildcard reaches Certificate Transparency |
| `nginx` | port 80, and the optional egress-address echo |
| `fail2ban` | the sshd, recidive and panel address-limit jails, each proven to read the log it is meant to |
| `metrics` | a ten-minute sampler of what the panel does not know, and the read-only export the master pulls |
| `reporter` | the Monday letter, built from the panel's database and the fleet's metric stores; master only |
| `checker` | the half-hourly self-check, mailed on failure straight past the master |
| `warp` | Cloudflare WARP as a local proxy, with a watchdog that counts its own restarts |
