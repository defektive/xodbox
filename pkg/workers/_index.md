---
title: Workers
description: Periodic background jobs
weight: 20
---

Workers are periodic background jobs that run inside the xodbox process
on a configurable schedule. They are the complement to [Notifiers](../notifiers):
notifiers react to inbound events in real time; workers run independently
of traffic and operate on the captured data (pruning old records,
aggregating stats, etc.).

Workers are registered in `xodbox.yaml` under a top-level `workers:` key,
following the same `key: value` map convention used by handlers and notifiers.

## Schedule expressions

The `schedule` key accepts any [robfig/cron v3](https://pkg.go.dev/github.com/robfig/cron/v3)
expression:

| Expression | Meaning |
|---|---|
| `@daily` | Once a day at midnight |
| `@hourly` | Once an hour |
| `@every 30m` | Every 30 minutes |
| `@every 6h` | Every 6 hours |
| `0 2 * * *` | Standard 5-field cron (daily at 02:00) |
| `*/15 * * * *` | Every 15 minutes |

## Behaviour

- If a worker is still running when its next tick fires, the new tick is
  **silently skipped** — there is no pileup.
- A worker error is logged but does not stop the scheduler; the worker
  will run again on the next tick.
- Workers are shut down gracefully: on SIGINT/SIGTERM xodbox cancels the
  context passed to `Run` and waits for any in-flight run to complete
  before exiting.

## Example

```yaml
workers:
  ## Docs: https://defektive.github.io/xodbox/docs/pkg/workers/purge/
  - worker: purge
    schedule: "@daily"
    max_age_days: "30"
    vacuum: "true"
```

## Running a job manually

A worker does not have to wait for its next tick. There are two ways to run
one on demand, and which you want depends on whether the server is running.

### Admin console (server running)

The **Jobs** page lists every configured worker with its schedule, next fire
time, and the outcome of its last run — how long it took, and any error. Press
**Run now** to start one immediately.

The job runs inside the live xodbox process, so it shares the server's database
connection and will not fight it for SQLite's write lock. This is the right
choice while `xodbox serve` is up. The page is admin-only, since a job like
[`purge`](purge/) deletes data permanently.

Under the hood:

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/workers` | `GET` | List workers and their last-run status. |
| `/api/workers/{name}/run` | `POST` | Start an out-of-schedule run. |

The run endpoint replies `202 Accepted` as soon as the run is accepted rather
than waiting for it to finish — a purge that vacuums a large database can take
minutes. Poll `GET /api/workers` for the outcome. It replies `404` for an
unknown worker and `409` when a run is already in flight: a worker never
overlaps with itself, whether the runs are scheduled or manual.

### CLI (server stopped)

```sh
xodbox workers list          # what is configured, and on what schedule
xodbox workers run purge     # run it now, in the foreground
```

`workers run` waits for the job to finish and exits non-zero if it fails, which
makes it usable from an external scheduler. Ctrl-C cancels the run's context.

This opens its own connection to `xodbox.db`. If `xodbox serve` is running
against the same file, a write-heavy job — the purge worker's `VACUUM` in
particular — can block or fail on SQLite's write lock. Use the admin console
instead, or stop the server first.

An empty `workers list` is the answer to "why did my background job never run?":
no `workers:` block means no job is ever scheduled.

## Available workers

| Worker | Description |
|---|---|
| [`purge`](purge/) | Delete interactions older than N days |
