# Metrics API

Every node serves its metric store as JSON over plain HTTP on its tailnet address. The weekly letter reads the fleet through it, the master's own store included, and a dashboard can read it the same way. The paths, parameters, shapes and status codes follow the mail host's `mail-stats` API, so one client can ask both

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

## Metrics

The collector, `roles/metrics/files/skibidi-metrics.py`, is the list: each probe names the metrics it writes, and `COUNTERS` and `DIMENSIONS` beside them say which are counters and what their detail means
