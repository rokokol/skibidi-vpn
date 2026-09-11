# Workarounds

Things in these roles that exist only because upstream is missing or broken something, with the upstream report where one was filed and what would retire each. A reader who finds one of these and "tidies" it undoes a decision; this file is where the decision is written down

## The panel installer is run, not replaced, and pinned by digest

`install.sh` does more than download: it installs the panel's dependencies, lays out the binary and the unit for the distribution, generates the first credentials and base path, runs `x-ui migrate` and writes the fail2ban files. Replacing it with tasks would mean carrying a copy of it and chasing every release. So the role fetches it at the commit the release tag points to, checks its sha256 before bash sees it, and runs it from disk. The management script it leaves at `/usr/bin/x-ui` is fetched from `main` by the installer whatever tag it was given, and the panel runs that script as root from its menu, so the role puts the script back at its own pinned digest afterwards

Reported: [MHSanaei/3x-ui#6391](https://github.com/MHSanaei/3x-ui/pull/6391), x-ui.sh and the units fetched from the installed tag; merged into `main` on 2026-09-03, not yet in a release. Retired by: pinning the first release that carries it; then the script the installer leaves is already the pinned one, and the put-back task can go

## The panel binary is pinned on the way out, not the tarball on the way in

The one thing the installer downloads that cannot be checked beforehand is the release tarball: the installer fetches it inside itself and unpacks it at once, so the role never holds the file, and upstream publishes no digest to hold it to. The role pins what comes out instead, the sha256 of `/usr/local/x-ui/x-ui`, on every run rather than only after an install, so a tampered download and a panel updated from its own menu fail the deploy the same way. The Xray binary beside it is deliberately not pinned: the panel is allowed to switch cores from its own UI, and that is the panel's domain

Reported: [MHSanaei/3x-ui#6393](https://github.com/MHSanaei/3x-ui/pull/6393), SHA-256 sidecars in releases and verification in install.sh and update.sh; open. Retired by: pinning the first release that carries it; the binary digest can then stay as a cheap second check or go, since the installer will have verified the tarball before unpacking it

## The panel's database is closed by the role, after the panel opened it

The panel creates `/etc/x-ui` at 0755 and its database, write-ahead log and shared memory under the default umask, which makes every client credential and every Reality private key readable by any local account, including the unprivileged one the metrics export runs as. The role sets the directory to 0700 and everything named after the database to 0600 on every run, takes its own backups under `umask 077`, and the checker turns red on anything looser

Reported: [MHSanaei/3x-ui#6390](https://github.com/MHSanaei/3x-ui/pull/6390), the SQLite store created 0700/0600; merged into `main` on 2026-09-03, not yet in a release. Retired by: pinning the first release that carries it; the role's tasks then find nothing to change and can go, and the checker's assertion stays as the proof

## The weekly report reads the panel's database, not its API

The panel's CLI cannot read a token back, only mint one, and minting rotates the single token it owns: every run knocked out whoever else held it, including the admin skill's registry entry. The report therefore reads `x-ui.db` on the master, opened read-only, from the tables the panel has carried since its first releases: `inbounds`, `client_traffics`, `settings` and `nodes`. The price is a coupling to the schema rather than to the API, paid at the deploy-time rehearsal, where a renamed column fails the letter in front of someone rather than on a Monday

Retired by: a CLI or API that issues a named, scoped token without rotating another; then the report could go back to the contract the skill uses

## acme.sh's recorded reload command is read out of its own config

Renewal runs acme.sh's cron, and the reload command that has to restart the panel lives in acme.sh's per-domain conf, base64-wrapped between `__ACME_BASE64__START_` and `__ACME_BASE64__END_` markers. The role reads it back to decide whether `--install-cert` needs to run again, which is the only way a changed reload command reaches an existing certificate. A version of this that missed the markers decoded nothing, never matched, reinstalled the certificate on every deploy and restarted the panel each time

Retired by: acme.sh exposing the recorded command through its CLI; until then the markers are part of the contract this role reads

## The geo databases are refreshed by a timer of ours, not by the core's own

Xray has an updater built in. The pinned core parses a `geodata` block and validates its cron — measured on 26.7.28: `{"geodata":{"cron":"0 4 * * *"}}` loads, `{"geodata":{"cron":"not-a-cron"}}` fails with "failed to build geodata configuration" — and the panel passes the block through (`internal/xray/config.go`) and offers the field in its own UI. Its install path is better than anything reachable from outside: it stages, swaps with backups, reloads the IP and domain registries in place and rolls the transaction back on failure, so the databases change under a running core with no restart and no dropped connection.

The `geodata` role does not use it, and the reason is what that updater leaves out. It fetches unconditionally — no `If-Modified-Since`, no ETag — so every node would pull the full set on every tick forever, where the role's conditional request makes an unchanged day cost nothing. And it verifies nothing: its only check is that the download was non-empty, while all three upstreams publish a `sha256sum` beside each file. The role pays for verification and for near-zero bandwidth with a restart of the core on the days the data actually changes, which is seconds of dropped connections. Neither side dominates; this is the trade chosen deliberately, and the honest summary is that correctness won over disruption.

Reported: [MHSanaei/3x-ui#6404](https://github.com/MHSanaei/3x-ui/pull/6404), the panel's own geofile download verified against the published digest — the geofile path was the last unverified download left in the panel, since the Xray binary is already checked against its `.dgst` sidecar; open. Retired by: verification reaching the core's own updater. The day it checks digests, this role hands the job over and the fleet gets hot reloads for free — the role's remaining value would be the conditional fetch alone, which is not worth a timer