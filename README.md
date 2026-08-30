# skibidi-vpn

Ansible roles that build and maintain a 3x-ui VPN node on Ubuntu — the panel, its certificate, the tunnel, the firewall and the periodic checks. The roles are generic; the fleet they are pointed at is not part of this repository

## What this covers, and what it does not

The split follows the database. Everything inside `/etc/x-ui/x-ui.db` — inbounds, clients, routing rules, panel settings — is administered through the panel API by the [xui-admin](https://github.com/rokokol/xui-admin) skill and is covered by the database backup. This repository owns everything outside it: packages, kernel settings, the firewall, the tunnel, nginx, certificates, timers and the backup mechanism itself

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
export XUI_NODES_DIR=/path/to/private/nodes       # the xui-admin skill
```

One registry, two consumers. A node file must be `chmod 600`; the inventory refuses to read one that anyone else can open, and strips the panel token from host variables so it never reaches `ansible-inventory --list` output

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
nix flake check
```

`molecule test` builds a real Ubuntu VM under KVM and runs the roles against it. A container is not enough here: systemd, the firewall and the tunnel are three of the things worth testing, and none of them behave in one

## Roles

| Role | What it owns |
| --- | --- |
| `common` | congestion control, queue discipline, conntrack limits, one outgoing address family |
| `firewall` | ufw policy, the three public ports, and hiding the tunnel's direct path |
| `tailscale` | the private network the panel is reachable on |
| `xui` | the pinned panel, bound to the tunnel address, asserted afterwards |
| `certs` | a wildcard certificate over DNS-01, so only the wildcard reaches Certificate Transparency |
| `nginx` | port 80, and the optional egress-address echo |
