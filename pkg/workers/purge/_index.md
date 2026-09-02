---
title: Purge
description: Delete old interactions on a schedule
weight: 1
---

Deletes interaction records older than a configurable number of days, along
with any files they captured, and reclaims the space on disk. Run this to keep
the SQLite database from growing unbounded during long-running engagements.

## Configuration

| Key            | Required | Default  | Notes                                                            |
|----------------|----------|----------|------------------------------------------------------------------|
| `worker`       | yes      | —        | Must be `purge`.                                                 |
| `schedule`     | no       | `@daily` | Cron expression or `@every` interval. See [Workers](../).        |
| `max_age_days` | no       | `30`     | Interactions older than this many days are deleted. Must be ≥ 1. |
| `vacuum`       | no       | `true`   | Run `VACUUM` after a purge that deleted rows, shrinking the database file. |

## Example

```yaml
workers:
  # Delete interactions older than 14 days, every night at 02:00.
  - worker: purge
    schedule: "0 2 * * *"
    max_age_days: "14"
    vacuum: "true"
```

## What gets deleted

Each run:

1. Permanently deletes interactions older than `max_age_days`, together with
   their `uploaded_files` rows and BLOBs.
2. Sweeps any rows left soft-deleted by an earlier version of xodbox or by the
   UI/API delete actions. These are invisible to every query but still occupy
   the database file.
3. Runs `VACUUM` (unless `vacuum: "false"`) to return the freed pages to the
   filesystem.

Deletes are permanent — there is no undo, and nothing in the UI can recover a
purged interaction. Take a copy of `xodbox.db` first if the captured data
matters to an engagement.

## Notes

- **`VACUUM` rewrites the whole database.** It needs temporary free disk space
  roughly equal to the current size of `xodbox.db` and holds a write lock for
  the duration, during which inbound interactions are not persisted. On a very
  large database, schedule it for a quiet hour. Set `vacuum: "false"` to skip
  it — deletes still free the pages for SQLite to reuse, the file just won't
  shrink.
- `VACUUM` is skipped when a run's context is already cancelled (shutdown in
  progress) and when the run deleted nothing.
- Deduplicated uploads are handled correctly: files are stored once per SHA-256
  hash, and when the interaction holding the canonical copy is purged, the bytes
  are transferred to a surviving duplicate so its download keeps working.
- `max_age_days: "0"` (or any non-positive or unparseable value) is silently
  ignored and the 30-day default is used instead.
- Each run logs `purge complete` with the number of rows removed, and
  `vacuum complete` with `bytes_reclaimed`. If neither appears in the log, the
  worker is not configured — check for a `workers:` block in `xodbox.yaml`.
- To apply the policy without waiting for the next tick, press **Run now** on
  the admin console's Jobs page, or run `xodbox workers run purge` against a
  stopped server. See [Running a job manually](../#running-a-job-manually).
