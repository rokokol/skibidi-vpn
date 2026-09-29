# Workarounds

Things in these roles that exist only because upstream is missing or broken something, each with a removal check and the upstream report where one was filed. A reader who finds one of these and "tidies" it undoes a decision; this file is where the decision is written down. A permanent choice that differs from the obvious route is in `DEVIATIONS.md`

The entries that wait for a panel release share one check: whether the release pinned as `xui_version` contains the merge commit of a pull request. Set `pr` to the entry's number

```sh
v=$(sed -n 's/^xui_version: "\(.*\)"/\1/p' roles/xui/defaults/main.yml)
m=$(gh pr view "$pr" -R MHSanaei/3x-ui --json mergeCommit --jq .mergeCommit.oid)
gh api "repos/MHSanaei/3x-ui/compare/$m...v$v" --jq .status
```

`behind` or `diverged` -> the pin does not carry the change yet. `ahead` or `identical` -> it does

---

## The panel installer is run, not replaced, and pinned by digest

**Where:** `roles/xui/tasks/main.yml` and the pinned digests in `roles/xui/defaults/main.yml`

**Symptom it prevents:** the management script the installer leaves at `/usr/bin/x-ui` is fetched from `main` whatever tag the installer was given, and the panel runs that script as root from its menu. Without the put-back, the node runs an unpinned script as root

**Why this works:** `install.sh` does more than download: it installs the panel's dependencies, lays out the binary and the unit for the distribution, generates the first credentials and base path, runs `x-ui migrate` and writes the fail2ban files. Replacing it with tasks would mean carrying a copy of it and chasing every release. So the role fetches it at the commit the release tag points to, checks its sha256 before bash sees it, runs it from disk, and puts the script back at its own pinned digest afterwards

**Removal check:** the shared check above with `pr=6391`. `ahead` or `identical` -> the script the installer leaves is already the pinned one, and the put-back task can go

**Upstream:** [MHSanaei/3x-ui#6391](https://github.com/MHSanaei/3x-ui/pull/6391), x-ui.sh and the units fetched from the installed tag; merged and released

---

## The panel binary is pinned on the way out, not the tarball on the way in

**Where:** the binary digest check in `roles/xui/tasks/main.yml`, with the digest in `roles/xui/defaults/main.yml`

**Symptom it prevents:** a tampered release tarball installs without a check. The installer fetches it inside itself and unpacks it at once, so the role never holds the file, and upstream publishes no digest to hold it to

**Why this works:** the role pins what comes out instead, the sha256 of `/usr/local/x-ui/x-ui`, on every run rather than only after an install, so a tampered download and a panel updated from its own menu fail the deploy the same way. The Xray binary beside it is deliberately not pinned: the panel is allowed to switch cores from its own UI, and that is the panel's domain

**Removal check:** the shared check above with `pr=6393`. `ahead` or `identical` -> the installer verifies the tarball before unpacking it; the binary digest can stay as a cheap second check or go

**Upstream:** [MHSanaei/3x-ui#6393](https://github.com/MHSanaei/3x-ui/pull/6393), SHA-256 sidecars in releases and verification in install.sh and update.sh; merged and released

---

## The panel's database is closed by the role, after the panel opened it

**Where:** the permission tasks and the backups in `roles/xui/tasks/main.yml`, and the checker's assertion on them

**Symptom it prevents:** every client credential and every Reality private key is readable by any local account, including the unprivileged one the metrics export runs as

**Why it happens:** the panel creates `/etc/x-ui` at 0755 and its database, write-ahead log and shared memory under the default umask

**Why this works:** the role sets the directory to 0700 and everything named after the database to 0600 on every run, takes its own backups under `umask 077`, and the checker turns red on anything looser

**Removal check:** the shared check above with `pr=6390`. `ahead` or `identical` -> the role's tasks find nothing to change and can go; the checker's assertion stays as the proof

**Upstream:** [MHSanaei/3x-ui#6390](https://github.com/MHSanaei/3x-ui/pull/6390), the SQLite store created 0700/0600; merged and released

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
