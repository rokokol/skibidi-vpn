# Deviations

Things in these roles that read as workarounds and are not: permanent choices that differ from the obvious or documented route, with the trade behind each. A reader who finds one of these and "tidies" it undoes a decision; this file is where the decision is written down. Things that exist only because an upstream gap forces them live in `WORKAROUNDS.md`

---

## The panel installer is run, not replaced, and pinned by digest

**Where:** the installer tasks in `roles/xui/tasks/main.yml`, with the commit and the digest in `roles/xui/defaults/main.yml`

**Why it differs from the obvious route:** the obvious route for Ansible is to replace a vendor's installer with tasks. `install.sh` does more than download: it installs the panel's dependencies, lays out the binary and the unit for the distribution, generates the first credentials and base path, runs `x-ui migrate` and writes the fail2ban files. Replacing it would mean carrying a copy of it and chasing every release. So the role fetches it at the commit the release tag points to, checks its sha256 before bash sees it, and runs it from disk

**What returning to the obvious route breaks:** a copy of the installer in tasks drifts from the release it installs, and the first release that adds a step leaves every node without it

---

## The panel binary is pinned on the way out

**Where:** the binary digest check in `roles/xui/tasks/main.yml`, with the digest in `roles/xui/defaults/main.yml`

**Why it differs from the obvious route:** the installer already checks the release tarball against the digest the release publishes, so a second pin looks redundant. The role pins what comes out, the sha256 of `/usr/local/x-ui/x-ui`, on every run rather than only after an install: the pin is a statement about the node, not about a download. The Xray core beside it is held for a different reason, which `WORKAROUNDS.md` records under "Xray is held at a pinned release"

**What returning to the obvious route breaks:** a panel updated from its own menu goes unnoticed, and a node and its master drift apart in version, which node mode does not survive. A tarball the release itself replaced would also pass the installer's check, because the digest beside it is replaced with it

---

## The file-reading jails say `backend = auto` themselves

**Where:** `[3x-ipl]` and `[recidive]` in `roles/fail2ban/templates/jail.local.j2`, and the `fail2ban-client get <jail> logpath` checks in the role, the checker and the VM test

**Why it differs from the obvious route:** fail2ban drops a jail's `logpath` without a word the moment its backend starts with `systemd` (`jailreader.py`, 1.0.2), and Ubuntu 24.04 sets that backend for every jail in `jail.d/defaults-debian.conf`. The two jails therefore carry `backend = auto` explicitly, the line the panel's own jail file has, and each check asks for the file the jail actually opened. The line costs nothing and stays whatever upstream does: [fail2ban/fail2ban#4232](https://github.com/fail2ban/fail2ban/issues/4232), a warning when `logpath` is dropped under a systemd backend, was closed as not planned the same day. Upstream's answer is that such a warning existed once and was withdrawn because operators reported it as an error, and that the fault lies with the distribution's global `backend = systemd`, unnecessary since 1.1.1 lets `auto` fall back to the journal by itself when a jail's `logpath` matches no file and its filter sets `journalmatch`. That fallback is silent in its turn, so `fail2ban-client get <jail> logpath` remains the only local proof of what a jail opened, on 1.0.2 and after an upgrade alike, and the log file is created before the jail is loaded so the fallback has nothing to trigger on. The panel's own backend override moved to `jail.d` in [MHSanaei/3x-ui#6392](https://github.com/MHSanaei/3x-ui/pull/6392)

**What returning to the obvious route breaks:** a jail left on the distribution's backend loads, reports green and watches the journal, where neither the panel nor fail2ban itself ever writes

---

## The mail path leaves the tunnel, over TLS

**Where:** the mailer settings and the `checker_smtp_tls` check in `roles/checker/`

**Why it differs from the obvious route:** the alert intake is public, guarded by a source-address allowlist, because the two hosting providers between them leave exactly one port open (see the mail host's own deviations). Letters name every client and every node, so the mailer speaks STARTTLS and verifies the intake against the system trust store. `checker_smtp_tls: false` is accepted only for an intake on the tunnel, where WireGuard already encrypts and authenticates below SMTP

**What returning to the obvious route breaks:** plain SMTP to a public intake carries the name of every client and every node in the clear; the checker refuses `tls off` for any address outside `metrics_tunnel_ranges`

---

## The panel installer runs with no terminal on purpose

**Where:** the installer task in `roles/xui/tasks/main.yml`

**Why it differs from the obvious route:** `install.sh` decides whether to prompt by asking whether stdin is a terminal. Piping the script into bash hid this by accident, because the pipe was the stdin. The role runs it with stdin from `/dev/null` and `XUI_NONINTERACTIVE=1`, and hands the port and base path in through the `XUI_*` knobs upstream documents under `deploy/`, which is the unattended contract the installer offers; the listen address has no knob there and is set by the role afterwards. The pseudo-terminal is the only part upstream does not mention

**What returning to the obvious route breaks:** a session that arrives with a pseudo-terminal, molecule's or any `ssh -t`, makes the installer wait forever on a question nobody will answer

---

## The Tailscale auth key travels through a file in /run

**Where:** the join task in `roles/tailscale/tasks/main.yml`

**Why it differs from the obvious route:** the CLI accepts `--auth-key file:<path>`, so the key is written to a root-only file on tmpfs, used once, and removed. The file form is the right one whatever the docs say; [tailscale/tailscale#21084](https://github.com/tailscale/tailscale/issues/21084) asks the security KB to recommend it

**What returning to the obvious route breaks:** an argument sits in `/proc/<pid>/cmdline` for every process on the node while the join runs, and `no_log` only hides it from Ansible's output

---

## The apt signing keys are carried in the repository

**Where:** `roles/tailscale/files/tailscale-archive-keyring.gpg` and `roles/warp/files/cloudflare-warp-archive-keyring.gpg`

**Why it differs from the obvious route:** a key decides what apt trusts. Downloading it at deploy time and checking it against a digest pinned in the repository is the same trust as carrying the bytes, with a network round trip and a failure mode added, and neither vendor publishes a fingerprint to check against instead. Tailscale serves one key for every Ubuntu release (noble and jammy are byte-identical)

**What returning to the obvious route breaks:** a downloaded key adds a network failure mode to every deploy, and an unpinned one turns a rotation into silent trust in a new file rather than a diff here

---

## The metrics API is plain HTTP with no authentication

**Where:** `roles/metrics/templates/skibidi-metrics-api.socket.j2` and `skibidi-metrics-api@.service.j2`, the API in `roles/metrics/files/skibidi-metrics.py`, the daily check's reads in `roles/checker/files/skibidi-daily.py`, and the metrics API checks in `roles/checker/templates/skibidi-check.j2`. The contract is `docs/metrics-api.md`

**Why it differs from the obvious route:** the obvious route for data that leaves a host is TLS and a credential. The API serves on the tailnet alone, where WireGuard already encrypts every packet and authenticates its source by node key, and a TLS certificate or a token would add a secret to rotate on every node without adding a party that can be kept out. Reach is decided below HTTP instead: the socket is bound to the tunnel interface, admits tunnel sources alone, has no firewall rule of its own, and the checker turns red when any of the three drifts. The read side carries no privilege worth a credential either: a dynamic user that can only read one store, in a process without a network of its own. It replaced an SSH export with a forced-command key, which had to stop once Tailscale SSH took port 22 on the tailnet address, and whose guard was the one line between a key and a shell. The mail host's statistics API makes the same trade, so one dashboard reads both alike

**What returning to the obvious route breaks:** a token on every node is a secret in a file the registry must not hold and a vault must carry to each deploy, and a certificate on a tailnet address needs either a private CA every reader trusts or a public name that puts the node in Certificate Transparency

---

## The push to the station borrows the backup's account, host and rule

**Where:** `roles/metrics/templates/push.env.j2`, which turns `backup_url` into the target, `roles/metrics/files/skibidi_push.py`, which pushes, and the units that read the target file

**Why it differs from the obvious route:** the obvious route for a second service on the same station is its own address variable, its own account and its own password. The station puts both behind one htpasswd, and the instance label the Pushgateway accepts must equal the login, so a second account would be a second name for the same node. The push therefore reads the station from `backup_url`, the account from `backup_user`, the password from the backup role's root-only file at the moment it needs it, and asks `skibidi-backup target` whether the station may be reached over plain HTTP. Only the Pushgateway's port is new. A node without `backup_url` pushes nothing, so the dashboard and the backup switch on and off together

**What returning to the obvious route breaks:** a second copy of the address drifts from the backup's when a station moves, a second password is one more secret in the vault, and a second copy of the plain-HTTP rule is the copy that gets forgotten when the first one tightens

---

## The daily check reads the last record of the check and does not run it again

**Where:** `roles/checker/templates/skibidi-check.j2`, which writes `checker_result_file` as its last act, and `roles/checker/files/skibidi-daily.py`, which reads it

**Why it differs from the obvious route:** the obvious route for "list everything still open" is to run every check once more. Some checks keep a count between runs, the master's missed answers among them, and a second run each morning would count a miss twice and raise the alert early. The daily check therefore reads what the last run ended with, and treats a record older than the check's own silence limit as a finding in itself: a dead check timer must not replay its last failures as if they were fresh. The rules for everything the check does not test are in `roles/metrics/files/skibidi_problems.py` alone, and the check does not repeat them, so a fact is never listed twice in one mail

**What returning to the obvious route breaks:** the master check fires one day early after a bad night, and a second list of rules drifts from the first until the same trouble is listed in two words

---

## The collector is the only writer of a node's push group, and it replaces the group

**Where:** `roles/metrics/files/skibidi_push.py` (`PUT`), `roles/metrics/files/skibidi-metrics.py` (`traffic_text`), and the master's `skibidi-report traffic` in `roles/reporter/files/skibidi-report.py`, which writes a file and pushes nothing

**Why it differs from the obvious route:** the obvious route is for each program to push its own numbers with `POST`, which replaces only the metric families in its body and leaves the rest of the group alone. That leaves a series behind for good once the thing it described is gone: a solved problem is a `node_problem` series the next body no longer names, and a `POST` of a family that has no series left does not touch the family at all. The station alerts for as long as the series stays. `PUT` replaces the whole group, so the node says its complete state each time and anything missing from it is gone. That works only with one writer, because two writers wipe each other. The path allows one group per account, so the master's traffic cannot have a group of its own. The reporter therefore writes the traffic to a file, and the collector validates the file and adds it to its body. A file nobody refreshed is left out, so a stopped reporter cannot keep old numbers alive either

**What returning to the obvious route breaks:** with `POST` a recovered node keeps its alerts open, and with `PUT` from two programs the master's traffic and its samples take turns disappearing
