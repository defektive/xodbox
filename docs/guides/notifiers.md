---
title: Notifier Integration
description: Set up Slack, Discord, and webhook notifications for captured interactions
weight: 40
---

Notifiers deliver alerts when xodbox captures an interaction. Every
handler (HTTP, DNS, SMB, SSH, FTP, SMTP, TCP) emits events; notifiers
filter them and forward matches to external services.

Four notifiers ship built-in: **app_log** (structured log, enabled by
default), **slack**, **discord**, and **webhook** (generic HTTP POST).

## How filtering works

Each notifier has an optional `filter` key — a Go regular expression
matched against the event's canonical **filter string**. The filter
string has the form:

```
HANDLER ACTION DETAIL from IP[,IP...]
```

Examples:

| Event | Filter string |
|-------|---------------|
| HTTP GET to `/probe` | `HTTPX GET /probe from 203.0.113.9` |
| DNS A query for `c2.evil.com.` | `DNS A c2.evil.com. from 10.0.0.5` |
| SMB auth capture | `SMB Auth CORP\alice from 10.0.0.5` |
| SSH password attempt | `SSH PasswordAuth root from 10.0.0.5` |
| Admin login (with `notify_logins`) | `HTTPX Login alice from 10.0.0.5` |

The default filter is `.*` (match everything). Filters are compiled at
startup — an invalid regex prevents the notifier from loading.

### Common filter patterns

| Goal | Filter |
|------|--------|
| Only HTTP hits under `/x/` | `^HTTPX (GET\|POST\|HEAD\|DELETE\|PUT\|PATCH\|TRACE) /x/` |
| Captured SMB hashes | `^SMB Auth` |
| DNS lookups for a domain | `^DNS (A\|AAAA) .*\.evil\.com` |
| SSH login attempts as root | `^SSH \w+ root ` |
| Admin console logins | `^HTTPX Login` |
| Events from a specific IP | `from .*10\.0\.0\.5` |
| Everything (default) | `.*` |

## Slack

### Setup

1. Create a [Slack incoming webhook](https://api.slack.com/messaging/webhooks)
   in your workspace.
2. Copy the webhook URL (starts with `https://hooks.slack.com/services/...`).
3. Add to `xodbox.yaml`:

```yaml
notifiers:
  - notifier: slack
    url: https://hooks.slack.com/services/T00/B00/xxxx
    channel: "#security-alerts"
    author: xodbox
    author_image: ":skull:"
```

### Configuration

| Key | Required | Default | Notes |
|-----|----------|---------|-------|
| `notifier` | yes | — | Must be `slack`. |
| `url` | yes | — | Slack incoming webhook URL. |
| `channel` | no | — | Channel name or user ID to post to. |
| `author` | no | — | Username displayed in Slack. |
| `author_image` | no | — | Slack emoji code (e.g. `:pirate:`) for the avatar. |
| `filter` | no | `.*` | Go regexp against the filter string. |

### Message format

Slack messages include the event details, the raw request data in a code
block, and (for HTTP events) a `Replay:` code block with a reproducible
curl command.

## Discord

### Setup

1. In your Discord server, go to Server Settings → Integrations →
   Webhooks → New Webhook.
2. Select the target channel and copy the webhook URL.
3. Add to `xodbox.yaml`:

```yaml
notifiers:
  - notifier: discord
    url: https://discord.com/api/webhooks/1234567890/abcdef...
    author: xodbox
    author_image: https://example.com/avatar.png
```

### Configuration

| Key | Required | Default | Notes |
|-----|----------|---------|-------|
| `notifier` | yes | — | Must be `discord`. |
| `url` | yes | — | Discord webhook URL. |
| `author` | no | — | Username displayed in Discord. |
| `author_image` | no | — | Full image URL for the avatar (not an emoji code). |
| `filter` | no | `.*` | Go regexp against the filter string. |

Discord has no `channel` key — the target channel is determined by the
webhook URL itself.

### Message format

Same as Slack: event details, raw data code block, and optional curl
replay block.

## Webhook (generic)

The webhook notifier POSTs a JSON payload to any HTTP endpoint. Use it to
integrate with SIEMs, n8n, Tines, custom automation, or any service that
accepts webhooks.

### Setup

```yaml
notifiers:
  - notifier: webhook
    url: https://your-service.example.com/hooks/xodbox
    filter: "^HTTPX"
```

### Configuration

| Key | Required | Default | Notes |
|-----|----------|---------|-------|
| `notifier` | yes | — | Must be `webhook`. |
| `url` | yes | — | Any HTTP endpoint. Posted with `Content-Type: application/json`. |
| `filter` | no | `.*` | Go regexp against the filter string. |

### Payload format

```json
{
  "RemoteAddr": "203.0.113.5",
  "RemotePort": 54321,
  "UserAgent": "curl/8.0",
  "Data": "DELETE /probe HTTP/1.1\r\nHost: ...",
  "Details": "HTTPX: DELETE http://.../probe from 203.0.113.5:54321",
  "Curl": "curl -X DELETE ..."
}
```

The `Curl` field is only present for HTTP events; it is omitted for DNS,
SMB, SSH, and other handlers.

## App log (default)

The `app_log` notifier writes events to the structured application log.
It is enabled by default in the embedded config template.

```yaml
notifiers:
  - notifier: app_log
    filter: ".*"
```

Output includes a `curl` attribute for HTTP events.

## Multiple notifiers

You can configure multiple notifiers — including multiple instances of the
same type with different filters:

```yaml
notifiers:
  - notifier: app_log

  - notifier: slack
    url: https://hooks.slack.com/services/T00/B00/xxxx
    channel: "#all-interactions"

  - notifier: slack
    url: https://hooks.slack.com/services/T00/B00/yyyy
    channel: "#smb-hashes"
    filter: "^SMB Auth"

  - notifier: webhook
    url: https://siem.internal/api/events
    filter: "^(HTTPX|DNS)"
```

## Failure handling

- **HTTP 4xx/5xx from the target:** logged as an error but does not block
  other notifiers. A flaky webhook will not cause event loss.
- **Connection/transport failures** (DNS resolution, refused, timeout):
  the error is logged and propagated. Events are still delivered to other
  notifiers.
- Notifier failures never prevent event recording in the database — the
  interaction is always persisted regardless of notifier outcomes.
