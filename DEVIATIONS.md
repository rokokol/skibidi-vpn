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

**Why it differs from the obvious route:** the installer already checks the release tarball against the digest the release publishes, so a second pin looks redundant. The role pins what comes out, the sha256 of `/usr/local/x-ui/x-ui`, on every run rather than only after an install: the pin is a statement about the node, not about a download. The Xray core beside it is held for a different reason, which `WORKAROUNDS.md` records under "Xray is held at 26.7.11"

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
