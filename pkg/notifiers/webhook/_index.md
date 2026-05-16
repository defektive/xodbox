---
title: Webhook
description: Generic HTTP Webhook
weight: 1
---

POSTs every event (or every event whose `Data()` matches `filter`) as
a JSON object to a configured URL. Slack and Discord notifiers share
this codepath under the hood.

## Payload shape

```json
{
  "RemoteAddr": "203.0.113.5",
  "RemotePort": 54321,
  "UserAgent":  "curl/8.0",
  "Data":       "DELETE /probe HTTP/1.1\r\nHost: ...",
  "Details":    "HTTPX: DELETE http://.../probe from 203.0.113.5:54321"
}
```

## Configuration

| Key        | Required | Default | Notes                                                                          |
|------------|----------|---------|--------------------------------------------------------------------------------|
| `notifier` | yes      | —       | Must be `webhook`.                                                             |
| `url`      | yes      | —       | Destination URL. Posted with `Content-Type: application/json`.                 |
| `filter`   | no       | `.*`    | Go `regexp` syntax. Tested against the event's `Data()`; non-matches are dropped silently. |

## Failure handling

- 2xx/3xx responses are treated as success.
- 4xx/5xx responses log an error but do not propagate one up to the
  dispatcher (so a flaky webhook does not block other notifiers).
- Connection/transport failures (DNS, refused, timeout) propagate as
  errors and are surfaced in the app log.
