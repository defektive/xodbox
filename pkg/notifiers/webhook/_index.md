---
title: Webhook
description: Generic HTTP Webhook
weight: 1
---

POSTs every matching event as a JSON object to a configured URL. Slack
and Discord notifiers share this codepath under the hood, but `webhook`
can also be used directly as a standalone notifier — no custom code
required. This makes it the primary integration point for external
workflows: pipe NTLM hashes to a cracking service, forward SMB auth
events to n8n, send everything to a SIEM, etc.

## Payload shape

```json
{
  "RemoteAddr": "203.0.113.5",
  "RemotePort": 54321,
  "UserAgent":  "curl/8.0",
  "Data":       "DELETE /probe HTTP/1.1\r\nHost: ...",
  "Details":    "HTTPX: DELETE http://.../probe from 203.0.113.5:54321",
  "Curl":       "curl -X DELETE ..."
}
```

`Curl` is only populated for HTTP events; it is omitted for other handlers.

## Configuration

| Key        | Required | Default | Notes                                                                          |
|------------|----------|---------|--------------------------------------------------------------------------------|
| `notifier` | yes      | —       | Must be `webhook`.                                                             |
| `url`      | yes      | —       | Destination URL. Posted with `Content-Type: application/json`.                 |
| `filter`   | no       | `.*`    | Go `regexp` matched against `"HANDLER ACTION DETAIL from IP"`. See [Notifiers](../) for the full filter reference. |

## Example

```yaml
notifiers:
  # Forward every captured SMB hash to an external cracking pipeline.
  - notifier: webhook
    url: https://n8n.myteam.internal/webhook/ntlm-capture
    filter: "^SMB Auth"

  # Alert a SIEM on any /l path hit (the default notify path).
  - notifier: webhook
    url: https://siem.example.com/ingest/xodbox
    filter: "^HTTPX.*\\/l"

  # No filter — forward everything.
  - notifier: webhook
    url: https://my-siem.example.com/ingest
```

## Failure handling

- 2xx/3xx responses are treated as success.
- 4xx/5xx responses log an error but do not propagate it to the
  dispatcher (a flaky webhook does not block other notifiers).
- Connection/transport failures (DNS, refused, timeout) propagate as
  errors and are surfaced in the app log.
