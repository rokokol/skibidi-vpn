# Deviations

Things in these roles that read as workarounds, with why each is there and what would retire it. A reader who finds one of these and "tidies" it undoes a decision; this file is where the decision is written down. Each entry names the upstream report where one was filed.

## The panel installer is run, not replaced, and pinned by digest

`install.sh` does more than download: it installs the panel's dependencies, lays out the binary and the unit for the distribution, generates the first credentials and base path, runs `x-ui migrate` and writes the fail2ban files. Replacing it with tasks would mean carrying a copy of it and chasing every release. So the role fetches it at the commit the release tag points to, checks its sha256 before bash sees it, and runs it from disk. The management script it leaves at `/usr/bin/x-ui` is fetched from `main` by the installer whatever tag it was given, and the panel runs that script as root from its menu, so the role puts the script back at its own pinned digest afterwards

Reported: [MHSanaei/3x-ui#6391](https://github.com/MHSanaei/3x-ui/pull/6391), x-ui.sh and the units fetched from the installed tag. Retired by: that change landing at the pinned version; then the script the installer leaves is already the pinned one

## The panel binary is pinned on the way out, not the tarball on the way in

The one thing the installer downloads that cannot be checked beforehand is the release tarball: the installer fetches it inside itself and unpacks it at once, so the role never holds the file, and upstream publishes no digest to hold it to. The role pins what comes out instead, the sha256 of `/usr/local/x-ui/x-ui`, on every run rather than only after an install, so a tampered download and a panel updated from its own menu fail the deploy the same way. The Xray binary beside it is deliberately not pinned: the panel is allowed to switch cores from its own UI, and that is the panel's domain

Reported: [MHSanaei/3x-ui#6393](https://github.com/MHSanaei/3x-ui/pull/6393), SHA-256 sidecars in releases and verification in install.sh and update.sh. Retired by: that change landing at the pinned version

## The panel's database is closed by the role, after the panel opened it

The panel creates `/etc/x-ui` at 0755 and its database, write-ahead log and shared memory under the default umask, which makes every client credential and every Reality private key readable by any local account, including the unprivileged one the metrics export runs as. The role sets the directory to 0700 and everything named after the database to 0600 on every run, takes its own backups under `umask 077`, and the checker turns red on anything looser

Reported: [MHSanaei/3x-ui#6390](https://github.com/MHSanaei/3x-ui/pull/6390), the SQLite store created 0700/0600. Retired by: that change landing at the pinned version; the role's tasks then find nothing to change and can go

## The file-reading jails say `backend = auto` themselves

fail2ban drops a jail's `logpath` without a word the moment its backend starts with `systemd` (`jailreader.py`, 1.0.2), and Ubuntu 24.04 sets that backend for every jail in `jail.d/defaults-debian.conf`. A jail configured that way loads, reports green and watches the journal, where neither the panel nor fail2ban itself ever writes. `[3x-ipl]` and `[recidive]` therefore carry `backend = auto` explicitly, the line the panel's own jail file has, and the role, the checker and the VM test ask `fail2ban-client get <jail> logpath` for the file each jail actually opened

Reported: [fail2ban/fail2ban#4232](https://github.com/fail2ban/fail2ban/issues/4232), a warning when `logpath` is dropped under a systemd backend, with a diff; and [MHSanaei/3x-ui#6392](https://github.com/MHSanaei/3x-ui/pull/6392), the panel's backend override written to `jail.d` instead of `sed` on `jail.conf`. Retired by: nothing short of fail2ban refusing the combination; the explicit backend costs one line and stays

## The weekly report reads the panel's database, not its API

The panel's CLI cannot read a token back, only mint one, and minting rotates the single token it owns: every run knocked out whoever else held it, including the admin skill's registry entry. The report therefore reads `x-ui.db` on the master, opened read-only, from the tables the panel has carried since its first releases: `inbounds`, `client_traffics`, `settings` and `nodes`. The price is a coupling to the schema rather than to the API, paid at the deploy-time rehearsal, where a renamed column fails the letter in front of someone rather than on a Monday

Retired by: a CLI or API that issues a named, scoped token without rotating another; then the report could go back to the contract the skill uses

## The mail path leaves the tunnel, over TLS

The alert intake is public, guarded by a source-address allowlist, because the two hosting providers between them leave exactly one port open (see the mail host's own deviations). Letters name every client and every node, so the mailer speaks STARTTLS and verifies the intake against the system trust store, and the checker refuses `tls off` for any address outside `metrics_tunnel_ranges`. `checker_smtp_tls: false` is accepted only for an intake on the tunnel, where WireGuard already encrypts and authenticates below SMTP

Retired by: the intake moving onto the tailnet; then `smtp` becomes a tunnel address, TLS switches off, and the checker holds the address the way it holds the metrics pull

## The panel installer runs with no terminal on purpose

`install.sh` decides whether to prompt by asking whether stdin is a terminal. A session that arrives with a pseudo-terminal, molecule's or any `ssh -t`, made it wait forever on a question nobody would answer; piping the script into bash had hidden this by accident, because the pipe was the stdin. The role runs it with stdin from `/dev/null` and `XUI_NONINTERACTIVE=1`, and hands the port and base path in through the `XUI_*` knobs upstream documents under `deploy/`, which is the unattended contract the installer offers; the listen address has no knob there and is set by the role afterwards

Retired by: nothing; this is the documented way to drive the installer unattended, and the pseudo-terminal is the only part upstream does not mention

## The Tailscale auth key travels through a file in /run

An argument sits in `/proc/<pid>/cmdline` for every process on the node while the join runs, and `no_log` only hides it from Ansible's output. The CLI accepts `--auth-key file:<path>`, so the key is written to a root-only file on tmpfs, used once, and removed

Reported: [tailscale/tailscale#21084](https://github.com/tailscale/tailscale/issues/21084), the security KB should recommend `--auth-key=file:`. Retired by: nothing; the file form is the right one whatever the docs say

## The apt signing keys are carried in the repository

A key decides what apt trusts. Downloading it at deploy time and checking it against a digest pinned in the repository is the same trust as carrying the bytes, with a network round trip and a failure mode added, and neither vendor publishes a fingerprint to check against instead. Both keys are in their roles' `files/`; Tailscale serves one key for every Ubuntu release (noble and jammy are byte-identical), and a rotation shows up as a diff here rather than as silent trust in a new file

Retired by: a vendor publishing a fingerprint out of band, at which point a download checked against that fingerprint would do the same job with a shorter diff

## acme.sh's recorded reload command is read out of its own config

Renewal runs acme.sh's cron, and the reload command that has to restart the panel lives in acme.sh's per-domain conf, base64-wrapped between `__ACME_BASE64__START_` and `__ACME_BASE64__END_` markers. The role reads it back to decide whether `--install-cert` needs to run again, which is the only way a changed reload command reaches an existing certificate. A version of this that missed the markers decoded nothing, never matched, reinstalled the certificate on every deploy and restarted the panel each time

Retired by: acme.sh exposing the recorded command through its CLI; until then the markers are part of the contract this role reads
