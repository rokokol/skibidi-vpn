# Metrics API

Every node serves its metric store as JSON over plain HTTP on its tailnet address. The daily check reads its own node through it, and a dashboard can read any node the same way. The numbers also leave the node by a push, described under "The push" below. The paths, parameters, shapes and status codes follow the mail host's `mail-stats` API, so one client can ask both

The port is `metrics_api_port` in `roles/metrics/defaults/main.yml`. The examples below use `9099` and a tailnet address from the documentation range

## Who can reach it

There is no authentication. Three layers decide who reaches the API, and `DEVIATIONS.md`, "The metrics API is plain HTTP with no authentication", has the trade:

- The socket is bound to the tunnel interface (`BindToDevice=`), so a packet that arrives on any other interface finds no listener. A request from the node to its own tunnel address still matches
- The socket admits sources inside `metrics_tunnel_ranges` and localhost alone (`IPAddressAllow=`)
- The firewall has no rule for the port. The tunnel interface is admitted as a whole by the `firewall` role, and the checker fails on any rule that names the port without that interface

Each connection starts a fresh process as a dynamic user whose only privilege is read access to the store through `metrics_reader_group`. The process has no network of its own, a read-only file system, and opens the store with SQLite's read-only mode

## Conventions

- Only `GET` is served; any other method answers `501`
- Every answer is `application/json` with `Cache-Control: no-store`, compact and with sorted keys
- Query timestamps `from` and `to` are Unix seconds, and a window is half-open: `from` is in it, `to` is not. Both are optional: the default is the last 24 hours
- Timestamps in answers are Unix seconds where the name has no suffix (`from`, `to`, `bucket_start`) and microseconds where it ends in `_us`
- `metric` selects one metric by name. Without it, every metric is in the answer
- `dimensions` is an object that names what a sample's detail means: `{"jail": "sshd"}`, `{"unit": "x-ui"}`, `{"timer": "skibidi-check.timer"}`, or `{}` for a metric without one
- An answer cut at its row limit says `"truncated": true`. Ask again with a smaller window
- Errors are `{"error": "<reason>"}`: `400` for a bad parameter, `404` for any other path, `503` when the store cannot be opened

## `GET /v1/health`

The state of the collector. `status` is `ok` once the collector has finished a run, and `starting` before that. A reader decides itself how much lag is too much

```sh
curl http://100.64.0.7:9099/v1/health
```

```json
{"collected_through_us":1790006400123456,"collection_lag_seconds":212.4,"node":"node-a","samples":61842,"samples_newest_us":1790006400123456,"samples_oldest_us":1782230400654321,"status":"ok"}
```

## `GET /v1/samples`

The raw rows of a window, as the collector wrote them. Cumulative counters are their running totals here; `/v1/aggregates` turns them into deltas. A window is at most 31 days

```sh
curl 'http://100.64.0.7:9099/v1/samples?from=1790002800&to=1790006400&metric=f2b_banned_total'
```

```json
{"collected_through_us":1790006400123456,"from":1790002800,"rows":[{"dimensions":{"jail":"sshd"},"metric":"f2b_banned_total","ts_us":1790003012345678,"value":412.0}],"to":1790006400,"truncated":false}
```

## `GET /v1/aggregates`

Samples summed into buckets. `resolution` is `hour` (the default) or `day`, and buckets start on UTC boundaries. A bucket is in the answer when its start lies in the window, so a `from` inside an hour skips that hour rather than half-counting it. A window is at most the store's retention

Each row has a `kind`:

- `gauge`: `samples` is the number of samples in the bucket, `total` their sum, `minimum` and `maximum` their extremes. The mean is `total / samples`
- `counter`: each sample becomes its step from the sample before it in the same series, the last sample before the window included. A counter that went down was reset, and its step is the new value, never a negative number. `total` is the bucket's delta, `samples` the number of steps, and `minimum` and `maximum` the smallest and largest step

```sh
curl 'http://100.64.0.7:9099/v1/aggregates?resolution=day&from=1789401600&to=1790006400&metric=unit_restarts'
```

```json
{"from":1789401600,"resolution":"day","rows":[{"bucket_start":1789401600,"dimensions":{"unit":"x-ui"},"kind":"counter","maximum":1.0,"metric":"unit_restarts","minimum":0.0,"samples":144,"total":2.0}],"to":1790006400,"truncated":false}
```

## Panel state

A node answers for its own panel through the panel's API when its file sets `metrics_panel_enabled = true`, and adds `metrics_panel_tls = true` when that panel serves TLS. The default is off: a node that does not ask for it installs nothing, and a deploy removes the credential file an earlier one wrote

The token comes from `vault.yml`, under `metrics_panel_secrets.<node name>.token`, not from the registry: the inventory drops every credential-shaped key before any role sees it. Create it in the panel with the `monitor` scope, which reaches the status and history routes and nothing that writes. An administrator token works and reaches far more than the collector needs

```yaml
metrics_panel_secrets:
  <node name>:
    token: <the panel's monitor-scope API token>
```

A node that enables panel state with no entry in the vault fails the deploy before anything is written, because the collector would otherwise push `x_ui_panel_up 0` every minute and say only that the API is unavailable

The role writes `/etc/skibidi/panel-metrics.json` as root, mode `0600`, and proves the token against the panel before the deploy finishes. The file holds `url`, `token` and `pin_sha256`. `url` is the panel the roles placed: the tunnel address, the panel port and the base path, over TLS when the node's file sets `metrics_panel_tls`. The pin is the SHA-256 of the certificate that handshake presents, taken from the handshake itself rather than from a file: the certificate names a domain, while the collector reaches the panel by an address it does not name. A node that sets `metrics_panel_tls` while its panel answers plain HTTP fails the deploy at that handshake. An empty pin means the system CA store answers instead. The collector refuses a file that group or others can open, refuses a redirect, and accepts plain HTTP only for a numeric address that belongs to the node itself

To rotate the token, create a new one in the panel, replace the vault entry and deploy; the old one keeps working until it is deleted in the panel. A rebuilt node restores the file from the vault and needs no other step

The existing push reads panel state on each run. It creates no separate service and no second push group

| Metric | Type | Meaning |
| --- | --- | --- |
| `x_ui_panel_up` | gauge | 1 when the status API returns valid state, otherwise 0 |
| `x_ui_xray_up` | gauge | 1 when the panel reports its local Xray as active, otherwise 0 |
| `x_ui_online_clients` | gauge | Latest online count for this panel and its child nodes, without duplicates |

All panel metrics use the push group's `job` and `instance` labels. A failed status query omits Xray and online values instead of reporting an unknown core as stopped. A failed or stale online query omits only the online value. The reader's `MAX_ONLINE_AGE` in `skibidi_panel.py` defines freshness. Zero clients is a valid sample; empty history is not

The online source is `GET /panel/api/server/history/online/2`, the panel's finest history resolution. A master includes its child nodes. Do not add a master's count to a child's count. This measures the panel's online definition, not open TCP sockets or successful end-to-end VPN connections

Pushgateway retains the last body when a node stops. Readers must also check `push_time_seconds` freshness before they treat panel state as current

## Metrics

The collector, `roles/metrics/files/skibidi-metrics.py`, is the list: each probe names the metrics it writes, and `COUNTERS` and `DIMENSIONS` beside them say which are counters and what their detail means

## The push

The same numbers leave the node a second way, for the station's dashboard. The collector's `push` command sends the newest value of every series to the Prometheus Pushgateway of the station that receives the node's backups, after each collection and on a timer of its own every `metrics_push_interval`. The push adds no row to the store, so its interval is free of the sampling's. The master pushes the panel's traffic besides, and every node pushes who knocks on it. A node whose file has no `backup_url` pushes nothing, and says so once in its journal

- The station is the backup station and the account is the backup account. `backup_url` names the host, `backup_user` the login, and the password is the backup role's root-only file `rest-password`. The Pushgateway's port is `metrics_push_port`, which the examples below call `9091`. The role writes the target to `metrics_push_env_file` for the units to read, and no secret is in it
- A push is `PUT /metrics/job/vpn/instance/<account>` with HTTP basic auth as that account. The station refuses any other path, any read, and an instance that is not the login. The job is always `vpn`, and a node has one group, so the station sees `instance=<account>` on every series and nothing about the path changed
- `PUT` replaces the whole group, and the collector's `push` is its only writer. A problem that was solved, a jail that went away and a traffic file that stopped arriving are missing from the next body and leave the station with it. A second writer would be wiped by every push or leave stale series behind, which is why the master's reporter writes its traffic to a file and the collector adds the file to its body
- Plain HTTP is accepted for a station inside the tunnel ranges and HTTPS anywhere, by the same rule as the backup. The push asks `skibidi-backup target` before it sends the password
- The body uses the Prometheus text format. OS and traffic names start with `vpn_`; panel state uses the explicit `x_ui_*` names in "Panel state". `node_problem` is the shared alert name. The `instance` label identifies the source node
- A push at least every quarter hour is the contract: the station alerts when `push_time_seconds` of a node is older than an hour. A push that fails is a line in the journal and costs no sample

```sh
curl -u node-a:<password> --data-binary @body.txt http://100.64.0.2:9091/metrics/job/vpn/instance/node-a
```

### What a node pushes

The newest sample of each series that is less than two hours old. A probe that stopped answering leaves the push when its last value gets that old, so a dead probe does not look alive. The names come from `PROMETHEUS` in the collector, and a test holds that table to the probes

| Metric | Type | Labels |
| --- | --- | --- |
| `vpn_load1`, `vpn_memory_used_ratio`, `vpn_disk_used_ratio`, `vpn_disk_total_bytes`, `vpn_uptime_seconds` | gauge | none |
| `vpn_cpu_busy_seconds_total`, `vpn_cpu_seconds_total` | counter | none |
| `vpn_conntrack_used_ratio`, `vpn_conntrack_entries` | gauge | none |
| `vpn_established_sockets`, `vpn_established_sockets_without_timer` | gauge | none |
| `vpn_fail2ban_failed_total`, `vpn_fail2ban_banned_total` | counter | `jail` |
| `vpn_fail2ban_banned` | gauge | `jail` |
| `vpn_unit_restarts_total` | counter | `unit` |
| `vpn_timer_last_fired_timestamp_seconds` | gauge | `timer` |
| `vpn_pending_updates`, `vpn_reboot_required` | gauge | none |
| `vpn_ufw_drops_total` | counter | none |
| `node_problem` | gauge | `key`, `summary` |

The station's alert rule reads `node_problem` without the `vpn_` prefix. It has one series of value `1` for each failure the last self-check recorded, with the help text "One unresolved problem this node reports of itself, by cause". `key` is the cause: letters, digits, dots, underscores and hyphens, the same on every run, with nothing in it that varies, so the station can keep one alert for it. `summary` is the first clause of the check's message, a short plain line that becomes the alert's subject. A record that is missing, or older than the check's silence limit, is one problem of its own with the key `check.record-missing` or `check.record-stale`. A clean check pushes no `node_problem` series at all, and a solved problem is missing from the next body. The quiet items of the daily check, such as pending updates and a required reboot, are not problems here. A failed check also triggers a push at once, from its alert unit, and mails only if that push fails

The firewall drops are counted per interval in the store. The push turns them into a running total that the collector keeps in the store's state, because a dashboard cannot add up an interval count that arrives again with every push

`vpn_cpu_seconds_total` is all CPU time the machine has had since boot, and `vpn_cpu_busy_seconds_total` is the part of it not spent idle. Busy is every state but idle, so iowait counts as busy and guest time, which the kernel already counts inside user and nice, is never added twice. The collector runs from a timer and never sees an interval go by, so the pair is the contract and the reader takes the rate of both: utilization is `rate(vpn_cpu_busy_seconds_total[1h]) / rate(vpn_cpu_seconds_total[1h])`. A reboot resets both, and a rate reads that as a counter reset

### Who knocks

The push reads fail2ban's own log, `metrics_fail2ban_log`, back to a day before the push, in every jail. The `jail` label says what a row is: the panel's address-limit jail finds the owner's own clients over their device limit, and the findings of recidive are the bans of other jails. A push names a few addresses only, because each address is a series of its own at the station

| Metric | Type | Labels |
| --- | --- | --- |
| `vpn_fail2ban_top_attempts` | gauge | `jail`, `ip` |
| `vpn_fail2ban_recent_ban_timestamp_seconds` | gauge | `jail`, `ip` |

`vpn_fail2ban_top_attempts` is the number of findings in the last day of each of the ten addresses that a jail found most, one series for each jail and address. `vpn_fail2ban_recent_ban_timestamp_seconds` is the time of each of the ten latest bans in the last day, and an address one jail banned twice is one series at its latest ban. A ban that fail2ban restores after a restart is not a new ban. A node without the log, or with no attempt in the day, pushes neither family

### What the master adds

The reporter's own timer writes the panel's traffic to `metrics_push_textfile` on a master that names a station, every `reporter_traffic_interval`, and the push adds the file to its body, in the same group as the master's samples. A file older than the push window, or one the station would refuse, is left out with a line in the journal. A panel that has counted nothing, or does not answer, leaves no file

| Metric | Type | Labels |
| --- | --- | --- |
| `vpn_inbound_traffic_bytes_total` | counter | `node`, `inbound`, `direction` |
| `vpn_client_traffic_bytes_total` | counter | `client`, `direction` |

`node` is the node the inbound runs on, as the panel names it. The master's own inbounds carry no node in the panel, so they take the master's inventory name. `inbound` is the panel's remark, and inbounds on one node that share a remark are added up under it. `direction` is `up` or `down`. `client` is the label the panel carries, which this repository already names in its letters and snapshots as the owner's own handle. A UUID, a subscription id or a key is never a label. The panel resets its counters when the owner does, and a reset is an ordinary counter reset
