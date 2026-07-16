---
title: Admin Console Setup
description: Bootstrap users, configure the admin web UI, and manage API keys and sinks
weight: 15
---

The admin console is an embedded React web UI and JSON API for managing
payloads, browsing captured interactions, creating sinks, and managing
users and API keys. It ships inside the xodbox binary — no separate
install needed.

## Bootstrap the first user

There is no default account. Create an admin user before starting the
server:

```sh
xodbox user add alice --admin
```

This prints a generated 24-character password once — store it
immediately. To choose your own password:

```sh
xodbox user add alice --admin --password 'your-strong-password'
```

Passwords must be at least 12 characters.

## Choose a serving strategy

The admin console can be served two ways:

### Option 1: Isolated listener (recommended)

Bind the admin console to a separate address, fully isolated from the
attacker-facing port:

```yaml
handlers:
  - handler: HTTPX
    listener: :80
    admin_listener: 127.0.0.1:9091
```

The admin UI is served only on `127.0.0.1:9091`. The main listener on
port 80 serves only honeypot content. This is the safest option — the
admin surface is not reachable from the attacker-facing port at all.

### Option 2: Same listener, sub-path

Mount the admin UI under a path prefix on the main listener:

```yaml
handlers:
  - handler: HTTPX
    listener: :80
    ui_path: /admin
```

The admin UI is served at `http://your-host/admin`. Use `ui_allow_cidrs`
to restrict access by source IP (see below).

## Restrict access by source IP

The `ui_allow_cidrs` config restricts admin UI access to specific source
IPs, checked against the **real TCP peer IP** (never `X-Forwarded-For`):

```yaml
handlers:
  - handler: HTTPX
    listener: :80
    admin_listener: 127.0.0.1:9091
    ui_allow_cidrs: "127.0.0.1/32,10.0.0.0/8"
```

Denied requests receive a `404` (indistinguishable from a non-existent
path). Empty or omitted means no restriction — authentication is still
required.

## Set the public URL

When the admin console runs on an isolated listener (different from the
honeypot), sink "Copy HTTP link" needs to know the honeypot's external
address:

```yaml
handlers:
  - handler: HTTPX
    listener: :80
    admin_listener: 127.0.0.1:9091
    public_url: https://oob.example.com
```

Without `public_url`, the link falls back to the admin UI's own origin,
which is only correct when the UI is served on the honeypot listener.

## Authentication

### Browser sessions

- Cookie-based with server-side session tokens (hashed at rest).
- `HttpOnly`, `SameSite=Strict`, `Secure` under TLS.
- State-changing requests require a **CSRF** token: the `X-CSRF-Token`
  header must echo the `xodbox_csrf` cookie.
- Login is rate-limited: 10 attempts per IP per minute (HTTP 429 when
  exceeded).

### API keys

API keys authenticate non-browser clients (scripts, CI, integrations).
They use the prefix `xdbx_` followed by 64 hex characters.

**Create a key** from the admin UI (Account → API Keys) or via the API:

```sh
curl -X POST https://admin:9091/api/apikeys \
  -H "Authorization: Bearer xdbx_existing_key" \
  -H "Content-Type: application/json" \
  -d '{"name": "ci-bot"}'
```

The full key is returned **exactly once** in the response — only the
SHA-256 hash is stored. Keys can optionally have an expiry
(`expires_at`).

**Use a key** by sending it as a Bearer token:

```sh
curl https://admin:9091/api/interactions \
  -H "Authorization: Bearer xdbx_your_key_here"
```

API key requests skip CSRF checks.

## User management

### CLI

```sh
xodbox user add bob                  # create user (role: user), prints generated password
xodbox user add carol --admin        # create admin
xodbox user add dave --password 'p'  # create user with a specific password
xodbox user list                     # list all users (ID, username, role)
xodbox user passwd bob               # reset password (revokes active sessions)
xodbox user rm bob                   # delete user + their keys and sessions
```

### API (admin only)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/users` | List all users |
| `POST` | `/api/users` | Create a user (`{"username": "...", "password": "...", "role": "admin\|user"}`) |
| `DELETE` | `/api/users/{id}` | Delete a user (cannot delete self or last admin) |
| `POST` | `/api/users/{id}/password` | Reset another user's password |

### Self-service

Any authenticated user can change their own password:

```
POST /api/account/password
{"current": "...", "new": "..."}
```

## Sinks

A **sink** is a named slug you embed in payloads to correlate
interactions. Creating a sink does not change what the honeypot
captures — it labels and groups hits so you can review them in one
place.

An interaction belongs to a sink when the slug appears in the
`request_target` (HTTP path, DNS qname) or the raw request headers. So
`/<slug>`, `<slug>.your.domain`, and `?x=<slug>` all correlate.

### CLI

```sh
SLUG=$(xodbox sink add --description "prod SSRF beacon")  # random slug (stdout is clean for scripting)
xodbox sink add my-label --description "a named one"       # explicit slug
xodbox sink list                                           # slug, hit count, description
xodbox sink rm my-label                                    # delete sink (interactions kept)
```

Slugs must be 6-64 characters of `[a-zA-Z0-9_-]`. Random slugs are
~10 characters of lowercase base32.

### API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/sinks` | List all sinks with event counts |
| `POST` | `/api/sinks` | Create (`{"slug": "...", "description": "..."}`) |
| `GET` | `/api/sinks/{slug}` | Sink detail + paginated events (`?limit=&offset=`) |
| `PUT` | `/api/sinks/{slug}` | Update description |
| `DELETE` | `/api/sinks/{slug}` | Delete sink (interactions kept) |

## Login notifications

Enable event emission on every successful admin login:

```yaml
handlers:
  - handler: HTTPX
    listener: :80
    admin_listener: 127.0.0.1:9091
    notify_logins: "true"
```

Login events appear in the Events log and fire notifiers whose filter
matches the pattern `HTTPX Login <username> from <ip>`. Failed login
attempts are not emitted.

## Real-time event streaming

The admin UI updates live via Server-Sent Events. The same stream is
available programmatically:

```sh
curl -N https://admin:9091/api/stream \
  -H "Authorization: Bearer xdbx_your_key" \
  -H "Accept: text/event-stream"
```

Filter the stream with query parameters: `handler`, `remote`, `target`,
`sink`.

## Example: full setup

```yaml
handlers:
  - handler: HTTPX
    listener: :80
    admin_listener: 127.0.0.1:9091
    ui_allow_cidrs: "127.0.0.1/32,10.0.0.0/8"
    public_url: https://oob.example.com
    notify_logins: "true"
```

```sh
# Create the first admin
xodbox user add operator --admin

# Start the server
xodbox serve

# Create a sink for an engagement
SLUG=$(xodbox sink add --description "Acme Corp SSRF test")
echo "Embed in payloads: https://oob.example.com/$SLUG"
```
