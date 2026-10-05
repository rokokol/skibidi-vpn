# Workarounds

Things in these roles that exist only because upstream is missing or broken something, each with a removal check and the upstream report where one was filed. A reader who finds one of these and "tidies" it undoes a decision; this file is where the decision is written down. A permanent choice that differs from the obvious route is in `DEVIATIONS.md`

---

## Xray is held at a pinned release

**Where:** the Xray tasks in `roles/xui/tasks/main.yml`, after the panel installer, with the version and both digests in `roles/xui/defaults/main.yml`; on every node

**Symptom it prevents:** with the core the pinned panel release bundles, the clients stop connecting. The master logs every attempt as `REALITY: processed invalid connection from …: authentication failed or validation criteria not met`, and the VPN is down for everyone until the core goes back

**Why it happens:** observed, not yet traced: the same clients and the same inbounds connect again as soon as the held core runs, so the break lies between the two cores. The bundled core's release notes name no REALITY change

**Why this works:** the role reads the digest of the core the panel runs. When it is not the pinned one, it fetches the official `Xray-linux-64.zip`, checked against the digest the release publishes, puts the `xray` inside in place and restarts the panel. It runs after the installer, because an install or an upgrade puts the bundled core back

**Removal check:** a newer core, tried on one node before the fleet

```sh
journalctl -u x-ui --since "-10min" | grep -c 'REALITY: processed invalid connection'
```

Run it on the node after switching its core from the panel's UI and connecting a client of every app in use. Non-zero -> put the held core back and keep the pin. Zero, and every client connects -> raise `xui_xray_version` to that core, or drop these tasks when the panel release bundles a core that passes

**Upstream:** not reported yet; the cause is not narrowed down enough to report

---

## The weekly report reads the panel's database, not its API

**Where:** `roles/reporter/files/skibidi-report.py`, which opens `x-ui.db` on the master read-only

**Symptom it prevents:** every report run knocks out whoever else holds the panel's API token, including the admin skill's registry entry

**Why it happens:** the panel's CLI cannot read a token back, only mint one, and minting rotates the single token it owns

**Why this works:** the report reads the tables the panel has carried since its first releases: `inbounds`, `client_traffics`, `settings` and `nodes`. The price is a coupling to the schema rather than to the API, paid at the deploy-time rehearsal, where a renamed column fails the letter in front of someone rather than on a Monday

**Removal check:** the panel's CLI and API issuing a named, scoped token without rotating another; then the report can go back to the contract the skill uses

**Upstream:** not reported yet

---

## acme.sh's recorded reload command is read out of its own config

**Where:** `roles/certs/tasks/main.yml`

**Symptom it prevents:** a changed reload command never reaches an existing certificate. A version of this that missed the markers decoded nothing, never matched, reinstalled the certificate on every deploy and restarted the panel each time

**Why it happens:** renewal runs acme.sh's cron, and the reload command that has to restart the panel lives in acme.sh's per-domain conf, base64-wrapped between `__ACME_BASE64__START_` and `__ACME_BASE64__END_` markers. acme.sh has no command that prints it

**Why this works:** the role reads the command back to decide whether `--install-cert` needs to run again, which is the only way a changed reload command reaches an existing certificate. Until acme.sh exposes it, the markers are part of the contract this role reads

**Removal check:** acme.sh exposing the recorded command through its CLI

**Upstream:** not reported yet

---

## The geo databases are refreshed by a timer of ours, not by the core's own

**Where:** the `geodata` role, `roles/geodata/`

**Symptom it prevents:** the core's own updater verifies nothing: its only check is that the download was non-empty, while all three upstreams publish a `sha256sum` beside each file. It also fetches unconditionally — no `If-Modified-Since`, no ETag — so every node would pull the full set on every tick forever

**Why it happens:** Xray has an updater built in. The pinned core parses a `geodata` block and validates its cron — measured on 26.7.28: `{"geodata":{"cron":"0 4 * * *"}}` loads, `{"geodata":{"cron":"not-a-cron"}}` fails with "failed to build geodata configuration" — and the panel passes the block through (`internal/xray/config.go`) and offers the field in its own UI. Its install path is better than anything reachable from outside: it stages, swaps with backups, reloads the IP and domain registries in place and rolls the transaction back on failure, so the databases change under a running core with no restart and no dropped connection

**Why this works:** the role's conditional request makes an unchanged day cost nothing, and it checks each file against the published digest. It pays for that with a restart of the core on the days the data actually changes, which is seconds of dropped connections. Neither side dominates; correctness won over disruption

**Removal check:** verification reaching the core's own updater. The day it checks digests, this role hands the job over and the fleet gets hot reloads for free — the role's remaining value would be the conditional fetch alone, which is not worth a timer

**Upstream:** [MHSanaei/3x-ui#6404](https://github.com/MHSanaei/3x-ui/pull/6404) verifies the panel's own geofile download against the published digest; merged and released. It covers the panel's download, not the core's updater

---

## restic comes from its release, not from Ubuntu

**Where:** the restic tasks in `roles/backup/tasks/present.yml`, with the version and both digests in `roles/backup/defaults/main.yml`; only on a node that names a backup station

**Symptom it prevents:** with Ubuntu's restic, the backup script cannot tell a repository that does not exist yet from one it cannot open. A wrong repository password or a station that refuses the account would then be answered with `restic init`, and the real fault would hide behind a second error

**Why it happens:** the script decides whether to create the repository by the exit code of `restic cat config`. restic returns 10 for a repository that does not exist only since 0.17.0 ([restic/restic#956](https://github.com/restic/restic/issues/956)). Ubuntu 24.04 ships 0.16.4 and 22.04 ships 0.12.1, and both return 1 for every failure. 22.04 also predates 0.16.1, which first reads the station account from `RESTIC_REST_USERNAME` and `RESTIC_REST_PASSWORD`, so it would need the password in the repository URL

**Why this works:** the role downloads the official `linux_amd64` build, checks the archive against the digest the release publishes in `SHA256SUMS`, and holds the installed binary to its own digest on every run, the same way the `xui` role holds the panel binary

**Removal check:** the Ubuntu release every node runs ships restic 0.17.0 or later

```sh
apt-cache policy restic | awk '/Candidate/ {print $2}'
```

Run it on a node of each Ubuntu release in the fleet. Every answer 0.17.0 or later -> the role can install Ubuntu's package instead, and drop the download and both digests. The binary digest check goes with them, because the package's digest changes with every security update

**Upstream:** nothing to report; a stable Ubuntu release does not take new upstream versions
