# Deviations

Things in these roles that read as workarounds and are not: deliberate choices that differ from the obvious or documented route, with the trade and what would reconsider each. A reader who finds one of these and "tidies" it undoes a decision; this file is where the decision is written down. Things that exist only because an upstream gap forces them live in `WORKAROUNDS.md`

## The file-reading jails say `backend = auto` themselves

fail2ban drops a jail's `logpath` without a word the moment its backend starts with `systemd` (`jailreader.py`, 1.0.2), and Ubuntu 24.04 sets that backend for every jail in `jail.d/defaults-debian.conf`. A jail configured that way loads, reports green and watches the journal, where neither the panel nor fail2ban itself ever writes. `[3x-ipl]` and `[recidive]` therefore carry `backend = auto` explicitly, the line the panel's own jail file has, and the role, the checker and the VM test ask `fail2ban-client get <jail> logpath` for the file each jail actually opened

Reported: [fail2ban/fail2ban#4232](https://github.com/fail2ban/fail2ban/issues/4232), a warning when `logpath` is dropped under a systemd backend, with a diff; closed as not planned the same day. Upstream's answer is that such a warning existed once and was withdrawn because operators reported it as an error, and that the fault lies with the distribution's global `backend = systemd`, unnecessary since 1.1.1 lets `auto` fall back to the journal by itself when a jail's `logpath` matches no file and its filter sets `journalmatch`. That fallback is silent in its turn, so `fail2ban-client get <jail> logpath` remains the only local proof of what a jail opened, on 1.0.2 and after an upgrade alike, and the log file is created before the jail is loaded so the fallback has nothing to trigger on. Also reported: [MHSanaei/3x-ui#6392](https://github.com/MHSanaei/3x-ui/pull/6392), the panel's backend override written to `jail.d` instead of `sed` on `jail.conf`; open. Retired by: nothing; upstream will not warn, and the explicit backend costs one line and stays

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