---
title: Purge
description: Delete old interactions on a schedule
weight: 1
---

Deletes interaction records older than a configurable number of days.
Run this to keep the SQLite database from growing unbounded during
long-running engagements.

## Configuration

| Key           | Required | Default  | Notes                                                       |
|---------------|----------|----------|-------------------------------------------------------------|
| `worker`      | yes      | —        | Must be `purge`.                                            |
| `schedule`    | no       | `@daily` | Cron expression or `@every` interval. See [Workers](../).   |
| `max_age_days`| no       | `30`     | Interactions older than this many days are deleted. Must be ≥ 1. |

## Example

```yaml
workers:
  # Delete interactions older than 14 days, every night at 02:00.
  - worker: purge
    schedule: "0 2 * * *"
    max_age_days: "14"
```

## Notes

- Uses GORM soft-delete (sets `deleted_at`), so the rows are not
  immediately reclaimed by SQLite. Run `VACUUM` manually if you need to
  shrink the file on disk after a large purge.
- `max_age_days: "0"` (or any non-positive value) is silently ignored and the
  30-day default is used instead.
