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
```

## Available workers

| Worker | Description |
|---|---|
| [`purge`](purge/) | Delete interactions older than N days |
