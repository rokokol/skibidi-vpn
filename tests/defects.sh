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
PUSH='roles/metrics/files/skibidi_push.py'
PROBLEMS='roles/metrics/files/skibidi_problems.py'
PUSH_ENV='roles/metrics/templates/push.env.j2'
METRICS_TASKS='roles/metrics/tasks/main.yml'
METRICS_DEFAULTS='roles/metrics/defaults/main.yml'
DAILY='roles/checker/files/skibidi-daily.py'
DAILY_SERVICE='roles/checker/templates/skibidi-daily.service.j2'
DAILY_TIMER='roles/checker/templates/skibidi-daily.timer.j2'
REPORTER_DEFAULTS='roles/reporter/defaults/main.yml'
REPORTER_TASKS='roles/reporter/tasks/main.yml'
ALERT_SCRIPT='roles/checker/templates/skibidi-alert.j2'
SITE='site.yml'
TAILSCALE_SSH='roles/tailscale/tasks/ssh.yml'
BACKUP='roles/backup/templates/skibidi-backup.j2'
BACKUP_SERVICE='roles/backup/templates/skibidi-backup.service.j2'
BACKUP_DEFAULTS='roles/backup/defaults/main.yml'
CHECK_DEFAULTS='roles/checker/defaults/main.yml'
JAILS='roles/fail2ban/templates/jail.local.j2'
FAIL2BAN_FACTS='roles/fail2ban/files/skibidi-fail2ban-facts.py'

# fail2ban

defect 'fail2ban/recidive-counts-clients' "$JAILS" \
  'filter = recidive[_jailname="(?:recidive|3x-ipl)"]' \
  '' \
  'a client over the device limit three times in a day is banned for a week on every port'

defect 'fail2ban/fleet-banned' "$JAILS" \
  'ignoreip = {{ (fail2ban_ignoreip + fail2ban_fleet_addresses) | join('"' '"') }}' \
  'ignoreip = {{ fail2ban_ignoreip | join('"' '"') }}' \
  'one node can ban the chain from the next as an attacker or a client over its limit'

defect 'fail2ban/attacker-lifted' "$FAIL2BAN_FACTS" \
  '        if causes and causes <= client_jails:' \
  '        if causes <= client_jails:' \
  'an attacker whose sshd bans rotated out of the log is lifted from recidive'

defect 'fail2ban/private-taken-for-public' "$FAIL2BAN_FACTS" \
  'if address.is_unspecified or address.is_multicast or any(address in network for network in INTERNAL):' \
  'if address.is_unspecified or address.is_multicast:' \
  'a node behind NAT puts its private address in the fleet list and never asks the cloud'

# The reporter

defect 'traffic/remark-collision' "$REPORT" \
  '        total = traffic["inbounds"].setdefault((node, name), {"up": 0, "down": 0})' \
  '        total = traffic["inbounds"][(node, name)] = {"up": 0, "down": 0}' \
  'two inbounds with one remark push the last one alone, or a body the station refuses'

defect 'traffic/credential-in-label' "$REPORT" \
  '        name = str(inbound.get("remark") or "") or' \
  '        name = str(inbound.get("settings")) or' \
  'every client UUID and subscription id goes to the station in a label'

defect 'traffic/every-inbound-on-the-master' "$REPORT" \
  'node = own_name if node_id is None else str(node_names.get(node_id, node_id))' \
  'node = own_name' \
  "the dashboard shows each node's inbounds as the master's"

defect 'traffic/node-by-id' "$REPORT" \
  'node = own_name if node_id is None else str(node_names.get(node_id, node_id))' \
  'node = own_name if node_id is None else str(node_id)' \
  'the dashboard names a node by a number nobody knows'

defect 'traffic/old-file-kept-when-empty' "$REPORT" \
  '    if not families:
        path.unlink(missing_ok=True)
        return 0' \
  '    if not families:
        return 0' \
  'a panel that counted nothing keeps the last numbers on the dashboard'

defect 'traffic/old-file-kept-on-panel-error' "$REPORT" \
  '        path.unlink(missing_ok=True)
        print(f"traffic: {error}", file=sys.stderr)' \
  '        print(f"traffic: {error}", file=sys.stderr)' \
  'a dead panel keeps its last traffic on the dashboard for as long as it stays dead'

defect 'reporter/old-snapshot-timer-kept' "$REPORTER_TASKS" \
  '    - skibidi-snapshot.timer
  register: reporter_old_timers' \
  '  register: reporter_old_timers' \
  'a timer of the deleted letter keeps firing into a script that no longer has its command'

defect 'reporter/gated-on-mail' "$SITE" \
  "      when: \"'master' in group_names\"" \
  "      when: \"'master' in group_names and reporter_to | length > 0\"" \
  'a master without an alert address gets neither its traffic on the dashboard nor its panel items'


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

# The push to the station

defect 'push/post-leaves-solved-problems' "$PUSH" \
  'method="PUT"' \
  'method="POST"' \
  'a problem that was solved stays in the group, and the station alerts on it for good'

defect 'push/wrong-instance' "$PUSH" \
  "instance/{urllib.parse.quote(user, safe='')}" \
  'instance/node' \
  'every node pushes into one group, and the station refuses the instance'

defect 'push/password-in-error' "$PUSH" \
  'raise PushError(f"the station answered HTTP {error.code}") from None' \
  'raise PushError(f"the station answered HTTP {error.code} {phrase}") from None' \
  'the station password lands in the journal at the first refusal'

defect 'push/guard-skipped' "$PUSH" \
  '    if station["guard"]:' \
  '    if False:' \
  'plain HTTP to a station outside the tunnel carries the password in the clear'

defect 'push/prefix-unchecked' "$PUSH" \
  'if not NAME.match(name) or not (name.startswith(PREFIX) or name in UNPREFIXED):' \
  'if not NAME.match(name):' \
  'a metric outside the vpn_ prefix is refused by the station, and so is the whole body'

defect 'push/label-unescaped' "$PUSH" \
  '    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"'"'"'"'"', '"'"'\\"'"'"')' \
  '    return str(value)' \
  'a quote or a newline in a client name breaks the exposition line and the whole push'

defect 'push/repeated-labels-unchecked' "$PUSH" \
  '            if key in seen:' \
  '            if False:' \
  'a repeated label set reaches the station, which refuses the body'

defect 'push/oldest-wins' "$PUSH" \
  'if key not in newest or ts >= newest[key][0]:' \
  'if key not in newest or ts <= newest[key][0]:' \
  'the dashboard shows the oldest sample of the window as the current one'

defect 'attackers/jail-unnamed' "$METRICS" \
  'attempts[(jail, address)] = attempts.get((jail, address), 0) + 1' \
  'attempts[("sshd", address)] = attempts.get(("sshd", address), 0) + 1' \
  "the operator's own clients over their device limit read as SSH attackers"

defect 'attackers/no-day-limit' "$METRICS" \
  'if match and stamp is not None and stamp >= cutoff:' \
  'if match and stamp is not None:' \
  'attempts from weeks ago are counted as the last day'

defect 'attackers/one-block-only' "$METRICS" \
  '            if stamp is not None and stamp < cutoff:' \
  '            if True:' \
  'a busy day longer than one block of the log loses its older half'

defect 'attackers/all-addresses' "$METRICS" \
  'busiest = sorted(attempts.items(), key=lambda item: (-item[1], item[0]))[:ATTACK_TOP]' \
  'busiest = sorted(attempts.items(), key=lambda item: (-item[1], item[0]))' \
  'every address that ever knocked becomes a series of its own at the station'

defect 'attackers/oldest-bans' "$METRICS" \
  'latest = sorted(bans.items(), key=lambda item: -item[1])[:ATTACK_TOP]' \
  'latest = sorted(bans.items(), key=lambda item: item[1])[:ATTACK_TOP]' \
  'the table of latest bans shows the oldest ones of the day'

defect 'attackers/first-ban-wins' "$METRICS" \
  'bans[(jail, address)] = max(bans.get((jail, address), 0.0), stamp)' \
  'bans.setdefault((jail, address), stamp)' \
  'an address banned again shows the time of its first ban'

defect 'attackers/restored-ban-counted' "$METRICS" \
  '\] (Found|Ban) (\S+)"' \
  '\] (?:Restore )?(Found|Ban) (\S+)"' \
  'a restart of fail2ban fills the table of latest bans with old bans'

defect 'collector/failed-push-fails-collect' "$METRICS" \
  '    if push:
        push_latest(now_us)' \
  '    if push:
        return push_latest(now_us)' \
  'a station that is down turns every sample into a failed run'

defect 'collector/note-every-run' "$METRICS" \
  'if state_value(connection, "push_unconfigured_noted") is None:' \
  'if True:' \
  'a node without a station fills its journal with the same line every ten minutes'

defect 'collector/dead-probe-pushed' "$METRICS" \
  '                (now_us - skibidi_push.LATEST_WINDOW_SECONDS * 1_000_000,),' \
  '                (0,),' \
  'a probe that stopped answering keeps pushing its last value for ninety days'

defect 'collector/ufw-total-restarts' "$METRICS" \
  'total = float(state_value(connection, UFW_TOTAL) or 0) + sum(counted)' \
  'total = sum(counted)' \
  'the dropped-packet counter resets every ten minutes'

defect 'collector/counters-as-gauges' "$METRICS" \
  '            "counter" if metric in COUNTERS else "gauge",' \
  '            "gauge",' \
  'the dashboard cannot take a rate of a total it was told is a level'

defect 'collector/label-named-detail' "$METRICS" \
  '        label = DIMENSIONS.get(metric, "detail")' \
  '        label = "detail"' \
  'the dashboard queries jail and unit and finds only a label called detail'

defect 'push/target-for-no-station' "$METRICS_TASKS" \
  '  when: backup_url | length > 0' \
  '  when: true' \
  'a node without a station is given an address to push to'

defect 'push/first-sample-pushes' "$METRICS_TASKS" \
  'argv: [/usr/local/sbin/skibidi-metrics, collect, --no-push]' \
  'argv: [/usr/local/sbin/skibidi-metrics, collect]' \
  'the first deploy pushes before the password file exists and logs a failure'

defect 'push/problems-not-installed' "$METRICS_TASKS" \
  '    - skibidi_problems.py
' \
  '' \
  'the daily check and the master import a module that is not on the node'

defect 'push/secret-in-target-file' "$PUSH_ENV" \
  'SKIBIDI_PUSH_USER={{ backup_user }}' \
  'SKIBIDI_PUSH_USER={{ backup_user }}
SKIBIDI_PUSH_PASSWORD={{ backup_rest_password }}' \
  'the station password sits in a world-readable file'

defect 'push/guard-dropped' "$PUSH_ENV" \
  'SKIBIDI_PUSH_GUARD="{{ backup_script }} target"
' \
  '' \
  'the push keeps no rule about plain HTTP, and nothing else enforces it for the push'

defect 'push/gateway-port' "$METRICS_DEFAULTS" \
  'metrics_push_port: 9091' \
  'metrics_push_port: 9092' \
  'every push goes to a port the station does not serve'

defect 'traffic/timer-too-slow' "$REPORTER_DEFAULTS" \
  'reporter_traffic_interval: 1min' \
  'reporter_traffic_interval: 5min' \
  "the dashboard's traffic lags the one-minute push by minutes"

# The open items and the daily check

defect 'problems/disk-limit-exclusive' "$PROBLEMS" \
  'if disk is not None and disk >= DISK_FULL:' \
  'if disk is not None and disk > DISK_FULL:' \
  'a disk exactly at the limit is not listed'

defect 'problems/reboot-blind' "$PROBLEMS" \
  'if latest.get(("reboot_required", "")):' \
  'if False:' \
  'a node that needs a reboot is never listed'

defect 'problems/updates-blind' "$PROBLEMS" \
  '    if updates:' \
  '    if False:' \
  'pending updates are never listed'

defect 'problems/collector-lag-blind' "$PROBLEMS" \
  'elif now - through / 1_000_000 > COLLECTOR_LAG_SECONDS:' \
  'elif False:' \
  'a collector that stopped hours ago leaves every number on the list stale and unflagged'

defect 'problems/expired-client-listed' "$PROBLEMS" \
  'if client["expires_days"] is not None and 0 <= client["expires_days"] <= EXPIRY_DAYS:' \
  'if client["expires_days"] is not None and client["expires_days"] <= EXPIRY_DAYS:' \
  'a client that expired a year ago is listed every morning'

defect 'problems/disabled-client-listed' "$PROBLEMS" \
  '        if not client["enable"]:
            continue' \
  '        if False:
            continue' \
  'a client switched off on purpose is listed every morning'

defect 'daily/stale-record-trusted' "$PROBLEMS" \
  '    if age > max_age_hours * 3600:' \
  '    if False:' \
  "the check's timer dies, the daily mail replays last week's failures as current, and the station alerts on them"

defect 'daily/missing-record-quiet' "$PROBLEMS" \
  '        return [("check.record-missing", "skibidi-check has not recorded a result on this node")]' \
  '        return []' \
  'a node whose check never ran reads as a node with nothing open, to the mail and to the station'

defect 'push/duplicate-cause-last-wins' "$METRICS" \
  '        found.setdefault(cause, skibidi_problems.summary(message))' \
  '        found[cause] = skibidi_problems.summary(message)' \
  'two failures of one cause are two series, or the later message hides the first'

defect 'push/traffic-file-unvalidated' "$METRICS" \
  '        skibidi_push.validate_text(text, taken)' \
  '        pass' \
  "one bad line in the master's traffic file makes the station refuse the body that is its sign of life"

defect 'push/stale-traffic-kept' "$METRICS" \
  '        if now - Path(path).stat().st_mtime > skibidi_push.LATEST_WINDOW_SECONDS:' \
  '        if False:' \
  'a reporter that stopped keeps its last traffic on the dashboard'

defect 'push/no-station-reads-as-pushed' "$METRICS" \
  '                return 3' \
  '                return 0' \
  'a node with no station skips its mail, and a failed check is heard by nobody'

defect 'problems/missing-and-stale-share-a-cause' "$PROBLEMS" \
  '        return [("check.record-stale",' \
  '        return [("check.record-missing",' \
  'a check whose timer died and a check that never ran are one alert with two remedies'

defect 'problems/summary-is-the-whole-message' "$PROBLEMS" \
  '    first = " ".join(message.split(";")[0].split())' \
  '    first = " ".join(message.split())' \
  'an alert subject runs on into the consequence and the details'

defect 'problems/cause-unsafe' "$PROBLEMS" \
  '    return re.sub(r"[^A-Za-z0-9._-]+", "-", text.strip()).strip("-") or "unknown"' \
  '    return text.strip() or "unknown"' \
  'a cause with a space or a slash in it breaks the matcher the station alerts by'

defect 'alert/station-last' "$ALERT_SCRIPT" \
  '        if {{ checker_alert_push }}; then' \
  '        if false; then' \
  'a failed check is mailed first and the station hears of it only if the mail node is alive'

defect 'alert/push-failure-swallowed' "$ALERT_SCRIPT" \
  '        if {{ checker_alert_push }}; then' \
  '        if {{ checker_alert_push }} || true; then' \
  'a push that failed or a node with no station is not mailed, and the failure is heard by nobody'

defect 'alert/every-unit-pushed' "$ALERT_SCRIPT" \
  '    skibidi-check | skibidi-check.service)' \
  '    *)' \
  'the daily list and a failed backup are swallowed by a push that has no series for them'

defect 'check/cause-not-recorded' "$CHECK" \
  "    failed=\"\${failed}\${cause}\"\$'\\t'\"\${*//\$'\\n'/ }\"\$'\\n'" \
  "    failed=\"\${failed}\${*//\$'\\n'/ }\"\$'\\n'" \
  'the record has messages and no causes, and the station sees one series named after a sentence'

defect 'push/prefix-exemption-wide' "$PUSH" \
  'UNPREFIXED = frozenset({"node_problem"})' \
  'UNPREFIXED = frozenset({"node_problem", "problem"})' \
  'a second name escapes the vpn_ prefix and collides with whatever else the station keeps'

defect 'push/check-settings-dropped' "$PUSH_ENV" \
  'SKIBIDI_CHECK_RESULT={{ checker_result_file }}
' \
  '' \
  'the node never says how many problems it has, and the station cannot hear a dead mail node'

defect 'daily/panel-failure-quiet' "$DAILY" \
  '    if done.returncode != 0:' \
  '    if False:' \
  'a master whose panel part crashed reads as a master with nothing open'

defect 'daily/api-silence-quiet' "$DAILY" \
  "        return [f\"the metrics API of this node did not answer: {getattr(error, 'reason', error)}\"]" \
  '        return []' \
  'a node whose metrics API is down reads as a node with nothing open'

defect 'daily/cut-answer-trusted' "$DAILY" \
  '    if answer.get("truncated"):' \
  '    if False:' \
  'a cut answer lacks the newest samples and the list is built from old ones'

defect 'daily/open-items-exit-zero' "$DAILY" \
  '    print(f"{len(found)} unresolved item(s) on {host}")
    return 1' \
  '    print(f"{len(found)} unresolved item(s) on {host}")
    return 0' \
  'the unit does not fail, the alert path does not run, and nothing is mailed'

defect 'daily/missing-settings-crash' "$DAILY" \
  '    if missing:' \
  '    if False:' \
  'a run without its settings dies in a traceback whose exit code reads as "something is open"'

defect 'daily/unit-without-settings' "$DAILY_SERVICE" \
  'EnvironmentFile={{ checker_daily_env_file }}
' \
  '' \
  'the timer runs a daily check that cannot find its record or its API'

defect 'daily/silent-failure' "$DAILY_SERVICE" \
  'OnFailure=skibidi-alert@%N.service
' \
  '' \
  'the daily check lists what is open into a journal nobody reads'

defect 'daily/timezone-dropped' "$DAILY_TIMER" \
  ":00:00 {{ checker_daily_timezone }}" \
  ":00:00" \
  'the list arrives at nine in the node'"'"'s own zone, which is not where the reader is'

defect 'daily/timer-unwatched' "$CHECK_DEFAULTS" \
  '  - name: skibidi-daily.timer
' \
  '  - name: skibidi-dailies.timer
' \
  'a daily check that stopped firing looks exactly like a node with nothing open'

defect 'check/record-skipped' "$CHECK" \
  'printf '"'"'%s'"'"' "$failed" > "$record.new" && mv "$record.new" "$record"' \
  'true' \
  'the daily check has no record to read, or reads one from an earlier day'

defect 'check/failure-not-recorded' "$CHECK" \
  "    failed=\"\${failed}\${cause}\"\$'\\t'\"\${*//\$'\\n'/ }\"\$'\\n'" \
  '    failed="${failed}"' \
  'the check fails and neither the daily list nor the station hears of it'

defect 'check/api-address-blind' "$CHECK" \
  'if [ "$api_inside" = "yes" ]; then' \
  'if true; then' \
  "a node's metrics cross the open internet in clear and the checker says nothing"
