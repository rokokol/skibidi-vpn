# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Node registry as a folder of TOML files, one per node, shared with the `xui-admin` skill so there is a single registry with two consumers. Groups come from each node's declared capabilities, so no role selects a node by name
- Roles `common`, `firewall`, `tailscale`, `xui`, `certs` and `nginx`: kernel and conntrack settings with one outgoing address family, a ufw policy that hides the tunnel's direct path, a pinned panel bound to the tunnel address and asserted afterwards, a DNS-01 wildcard certificate so only the wildcard reaches Certificate Transparency, and a port 80 that answers like an ordinary site
- `tests/no-secrets.sh`, a gate against a secret reaching a tracked file, proven by planting one
- Nix dev shell and a flake check running shellcheck
