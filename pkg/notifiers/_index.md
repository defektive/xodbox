---
title: Notifiers
description: Interaction notifiers
weight: 10
---

Notifiers are used to send notifications to external services or log interactions to the app log.

Available notifiers: `app_log`, `slack`, `discord`, `webhook`.

### Filters

Each notifier accepts a `filter` configuration option, compiled into a Go
regexp. The notifier only fires when the filter matches — this applies to
every notifier (`app_log`, `slack`, `discord`, `webhook`). The default
filter is `.*` (match everything).

The regexp is matched against a single **canonical string** that is
consistent across every handler:

```
HANDLER ACTION DETAIL from IP[,IP...]
```

- **HANDLER** — the handler name (`HTTPX`, `DNS`, `FTP`, `SMTP`, `SSH`,
  `TCP`, `SMB`).
- **ACTION** — the interaction kind (HTTP method, DNS query type, `Auth`,
  `Mail`, `Data`, …).
- **DETAIL** — handler-specific specifics (HTTP path+query, DNS name, SSH
  user, SMB account, …).
- **IP chain** — the unique source IPs. For HTTPX this is the
  de-duplicated `X-Forwarded-For` + `X-Real-Ip` + peer chain (client
  first); for other handlers it's the peer IP.

Because the shape is uniform, one regexp can select across any handler:

| Goal | Filter |
|------|--------|
| HTTP payload hits under `/x/` | `^HTTPX (GET\|POST) /x/` |
| Captured SMB hashes | `^SMB Auth` |
| DNS lookups for a C2 domain | `^DNS (A\|AAAA) .*\.evil\.com` |
| SSH login attempts as root | `^SSH \w+ root ` |
| Admin console logins (needs `notify_logins`) | `^HTTPX Login` |
| Anything from one source IP | `from .*10\.0\.0\.5` |

Example canonical strings:

```
HTTPX POST /x/beacon?id=1 from 203.0.113.9,10.0.0.1
HTTPX Login alice from 10.0.0.5
DNS A c2.evil.com. from 10.0.0.5
SMB Auth CORP\alice from 10.0.0.5
SSH PasswordAuth root from 10.0.0.5
```

The `HTTPX Login` events are only emitted when the HTTPX handler is configured
with `notify_logins: "true"` (see the [HTTPX handler](../handlers/httpx)).

Check each [handler](../handlers) for the exact `FilterString` its events
produce.
