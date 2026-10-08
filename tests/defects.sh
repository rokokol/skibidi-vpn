#!/usr/bin/env bash
# The defect list for this repository, read by `scripts/t.sh falsify`
#
# Needs bash 3.2, since falsify sources it wherever t.sh runs
#
# Each entry neuters one guard in the code and the unit tests must go red. The format is in
# `scripts/t.sh help falsify`; the run is
#
#   nix develop .#ci -c scripts/t.sh falsify -d tests/defects.sh [FILTER] -- python3 -m unittest discover -s tests -q
#
# FILTER runs only the defects whose name contains it. FIND must appear exactly once in
# FILE, or the entry is reported `stale`: the list has drifted from the code it describes
#
# shellcheck disable=SC2016 # every $ in a single-quoted text here is text to find, never an expansion

REPORT='roles/reporter/files/skibidi-report.py'
ALERT='roles/checker/files/skibidi-alert-html.py'
METRICS='roles/metrics/files/skibidi-metrics.py'
SOCKET='roles/metrics/templates/skibidi-metrics-api.socket.j2'
SERVICE='roles/metrics/templates/skibidi-metrics-api@.service.j2'
LEGACY='roles/metrics/tasks/legacy-ssh-export.yml'
CHECK='roles/checker/templates/skibidi-check.j2'
REPORT_CONFIG='roles/reporter/templates/report.toml.j2'
TAILSCALE_SSH='roles/tailscale/tasks/ssh.yml'
BACKUP='roles/backup/templates/skibidi-backup.j2'
BACKUP_SERVICE='roles/backup/templates/skibidi-backup.service.j2'
BACKUP_DEFAULTS='roles/backup/defaults/main.yml'
CHECK_DEFAULTS='roles/checker/defaults/main.yml'

# The weekly letter

defect 'counters/negative-week' "$REPORT" \
  '    return new - old if new >= old else new' \
  '    return new - old' \
  'a client counter reset turns into a negative week of traffic'

defect 'cid/attachment-drift' "$REPORT" \
  '            cid=f"<skibidi-{name}>",' \
  '            cid="<skibidi-chart>",' \
  'every chart renders as a broken-image icon in the letter'

defect 'escape/raw-text' "$REPORT" \
  '{style("p")}">{html.escape(text)}</p>'"'" \
  '{style("p")}">{text}</p>'"'" \
  'a client label chosen maliciously becomes live HTML in the mail client'

defect 'subject/alert-blind' "$REPORT" \
  '    prefix = "[!] " if data.get("alerts") else ""' \
  '    prefix = ""' \
  'trouble no longer reaches the subject line, so nobody opens the letter'

defect 'charts/dangling-cid' "$REPORT" \
  '        if png:
            charts[name] = png' \
  '        charts[name] = png' \
  'an empty week attaches nothing yet references it, or crashes the send'

defect 'window/weekday-blind' "$REPORT" \
  '    end -= dt.timedelta(days=(local.date().weekday() - weekday) % 7)' \
  '    _ = weekday' \
  'a delayed run reports a window that ends mid-week and nobody notices'

defect 'sanitise/credentials-through' "$REPORT" \
  '        clients.append(client_label(client.get("email")))' \
  '        clients.append(json.dumps(client))' \
  'the weekly snapshot in /var/lib carries every client UUID and subscription id'

defect 'diff/enable-blind' "$REPORT" \
  '        if was["enable"] != now["enable"]:' \
  '        if False:' \
  'an inbound switched off by mistake never appears in what-changed'

defect 'alerts/silent-absence' "$REPORT" \
  '    for name, reason in data.get("unreachable", []):' \
  '    for name, reason in []:' \
  'a node that did not answer reads as a healthy, quiet node'

defect 'pull/cut-week-accepted' "$REPORT" \
  '    if payload.get("truncated"):' \
  '    if False:' \
  'a week cut at the row limit is reported as a quiet week'

defect 'pull/master-skipped' "$REPORT_CONFIG" \
  "{% for host in ([inventory_hostname] + groups['nodes'] | default([])) | unique | sort %}" \
  "{% for host in groups['nodes'] | default([]) | sort if host != inventory_hostname %}" \
  "the letter no longer reads the master's own store"

# The alert mail

defect 'alert-mail/text-rewritten' "$ALERT" \
  '    message.set_content(body, charset="utf-8", cte="8bit")' \
  '    message.set_content("see the HTML part", charset="utf-8", cte="8bit")' \
  'a client without HTML loses the journal the alert exists to carry'

defect 'alert-mail/raw-journal-html' "$ALERT" \
  '{html.escape(line[4:].strip())}</li>'"'" \
  '{line[4:].strip()}</li>'"'" \
  'a journal line chosen maliciously becomes live HTML in the mail client'

defect 'alert-mail/fail-blends-in' "$ALERT" \
  '    if line.startswith("FAIL"):
        return "fail"' \
  '    if False:
        return "fail"' \
  'the one line that says what broke is styled like every passing check'

# The metrics API on the nodes

defect 'api/every-interface' "$SOCKET" \
  'BindToDevice={{ metrics_api_interface }}
' \
  '' \
  'the unauthenticated API answers on the public interface as soon as ufw slips'

defect 'api/any-source' "$SOCKET" \
  'IPAddressDeny=any
' \
  '' \
  'a source outside the tunnel is admitted by the socket'

defect 'api/range-ignored' "$METRICS" \
  'FROM samples WHERE ts_us >= ? AND ts_us < ?"' \
  'FROM samples WHERE ts_us >= ? OR ts_us < ?"' \
  'a history slice returns the whole store, and the letter counts every week as this one'

defect 'api/counters-raw' "$METRICS" \
  '            change = clamped_delta(value, previous)' \
  '            change = value' \
  'a dashboard sums running totals and shows thousands of bans an hour'

defect 'api/counter-reset-negative' "$METRICS" \
  '    return new - old if new >= old else new' \
  '    return new - old' \
  'a fail2ban restart turns into a negative number of bans'

defect 'api/counter-edge-lost' "$METRICS" \
  '            previous = baselines.get(previous_series)' \
  '            previous = None' \
  'the first step of every window is dropped at its edge'

defect 'api/half-bucket' "$METRICS" \
  '    first = -(-start // step) * step' \
  '    first = start // step * step' \
  'a window starting mid-hour reports a bucket it saw only half of'

defect 'api/writable-open' "$METRICS" \
  'f"file:{path or DB_PATH}?mode=ro"' \
  'f"file:{path or DB_PATH}?mode=rwc"' \
  'a node whose collector never ran reads as a healthy, empty store'

defect 'api/static-user' "$SERVICE" \
  'DynamicUser=yes' \
  'DynamicUser=no' \
  'every request runs as root, with write access to the store'

defect 'api/network' "$SERVICE" \
  'PrivateNetwork=yes' \
  'PrivateNetwork=no' \
  'a compromised request handler can open connections anywhere'

# The retired SSH export

defect 'cleanup/account-kept' "$LEGACY" \
  '    name: skibidi-metrics
    state: absent' \
  '    name: skibidi-metrics
    state: present' \
  'the old login account and its key stay on every node'

defect 'cleanup/key-kept' "$LEGACY" \
  '    path: /root/.ssh/skibidi-report
' \
  '    path: /root/.ssh/skibidi-report.old
' \
  'the master keeps a passphrase-less key nothing uses'

# The node health check

defect 'check/stray-listener-blind' "$CHECK" \
  "grep -v '%{{ metrics_api_interface }}:{{ metrics_api_port }}\$'" \
  "grep -v ':{{ metrics_api_port }}\$'" \
  'the API listening on every interface reads as healthy'

defect 'check/public-rule-blind' "$CHECK" \
  "\$1 ~ /^{{ metrics_api_port }}(\\/tcp)?\$/ && !/on {{ firewall_tunnel_interface }}/')" \
  "\$1 ~ /^{{ metrics_api_port }}(\\/tcp)?\$/ && /on {{ firewall_tunnel_interface }}/')" \
  'a ufw rule opening the API port to the world goes unnoticed'

defect 'check/store-mode-blind' "$CHECK" \
  'store_loose=$(find "$store_dir" -perm /o+rwx 2>/dev/null | wc -l)' \
  'store_loose=0' \
  'a world-readable journal file beside the store goes unnoticed'

# Tailscale SSH

defect 'tailscale/switch-mid-play' "$TAILSCALE_SSH" \
  '      - --on-active=10
' \
  '' \
  'Tailscale SSH takes over port 22 while the play still rides it'

defect 'tailscale/switch-every-run' "$TAILSCALE_SSH" \
  '  when: (tailscale_prefs.stdout | from_json).RunSSH | default(false) | bool != tailscale_ssh | bool' \
  '  when: true' \
  'every deploy reschedules the switch and is never idempotent'

# The backup channel

defect 'backup/silent-failure' "$BACKUP_SERVICE" \
  'OnFailure=skibidi-alert@%N.service
' \
  '' \
  'a backup that fails every night mails nobody'

defect 'backup/secret-in-unit' "$BACKUP_SERVICE" \
  'ExecStart={{ backup_script }} run
' \
  'Environment=RESTIC_REST_PASSWORD={{ backup_rest_password }}
ExecStart={{ backup_script }} run
' \
  'every local account reads the station password with systemctl show'

defect 'backup/secret-in-url' "$BACKUP_DEFAULTS" \
  'backup_repository: "rest:{{ backup_url | regex_replace' \
  'backup_repository: "rest:{{ backup_url'" | replace('://', '://' ~ backup_user ~ ':' ~ backup_rest_password ~ '@')"' | regex_replace' \
  'the station password sits in the script and in every restic error'

defect 'backup/init-every-run' "$BACKUP" \
  '        0) echo "the repository exists" ;;' \
  '        0) "$restic" init --quiet >/dev/null ;;' \
  'every run tries to create a repository that already exists'

defect 'backup/init-on-any-error' "$BACKUP" \
  '        10)
' \
  '        *)
' \
  'a wrong password is answered with a second repository attempt instead of an alert'

defect 'backup/file-copy' "$BACKUP" \
  "sqlite3 -cmd '.timeout 30000' \"\$source\" \".backup '\$copy'\"" \
  'cp "$source" "$copy"' \
  'the staged panel database misses whatever is still in its write-ahead log'

defect 'backup/integrity-unchecked' "$BACKUP" \
  "[[ \"\$(sqlite3 \"\$copy\" 'pragma integrity_check')\" == ok ]] ||" \
  'true ||' \
  'a store with a damaged page is pushed as if it could be restored'

defect 'backup/staged-world-readable' "$BACKUP" \
  '    umask 077
' \
  '    umask 022
' \
  'the staged copy of every client credential is readable by every account'

defect 'backup/guard-skipped' "$BACKUP" \
  '    target >/dev/null
' \
  '' \
  'plain HTTP to a station outside the tunnel carries the database in the clear'

defect 'backup/guard-blind' "$BACKUP" \
  'if not any(address in network for network in ranges))' \
  'if False)' \
  'a station outside the tunnel passes the guard'

defect 'backup/https-refused' "$BACKUP" \
  'if parts.scheme == "https" and parts.hostname:' \
  'if False:' \
  'a station behind TLS outside the tunnel is refused, which the contract allows'

defect 'backup/shared-repository' "$BACKUP_DEFAULTS" \
  '}}/{{ backup_user }}/"' \
  '}}/"' \
  "every node pushes to the station's root, which a private-repos station refuses"

defect 'check/backup-timer-blind' "$CHECK" \
  'if systemctl is-enabled --quiet skibidi-backup.timer 2>/dev/null \
    && systemctl is-active --quiet skibidi-backup.timer; then' \
  'if true; then' \
  'a node whose backup timer was disabled reads as healthy'

defect 'check/backup-target-blind' "$CHECK" \
  'if backup_target=$({{ backup_script }} target 2>&1); then' \
  'if backup_target=$(echo inside); then' \
  'a registry edit that moves the station off the tunnel goes unnoticed until the push'

defect 'check/backup-modes-blind' "$CHECK" \
  '    backup_open=$(find {{ backup_config_dir }} {{ backup_state_dir }} \( -perm /077 -o ! -user root \) 2>/dev/null | wc -l)' \
  '    backup_open=0' \
  'a backup secret readable by every account goes unnoticed'

defect 'check/backup-always' "$CHECK" \
  "{% if backup_url | default('') | length > 0 %}
" \
  '{% if true %}
' \
  'a node that names no station fails its checks for a backup it never had'

defect 'check/backup-timer-unwatched' "$CHECK_DEFAULTS" \
  '  - name: skibidi-backup.timer
' \
  '  - name: skibidi-backups.timer
' \
  'a backup timer that stopped firing is never noticed'
