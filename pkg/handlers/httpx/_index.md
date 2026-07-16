---
title: HTTPX
description: HTTPX Handler
weight: 10
---

## Purpose

The primary HTTP/HTTPS listener. It serves user-defined payloads
keyed by URL pattern, hosts static assets, exposes a private JSON
API, and can transparently provision Let's Encrypt certificates via
ACME-DNS-01. Every request produces an `InteractionEvent` so
out-of-band HTTP reach-out from an application under test can be
asserted against expected paths and headers.

## Replaying captured requests (SSRF)

Every HTTP interaction can render a `curl` command that reproduces the
captured request — method, target URL, all headers, and the body. Notifiers
include it automatically: `slack`/`discord` add a `Replay:` code block,
`webhook` adds a `Curl` JSON field, and `app_log` logs a `curl` attribute.

This is aimed at SSRF: when a vulnerable server is coerced into calling
xodbox, the captured request often carries the headers, cookies, or
cloud-metadata tokens the victim attached. Copy the generated command,
swap the URL for the intended internal target, and re-run it from the CLI
to inspect that service with the victim's own request:

```sh
curl -X POST 'http://your-xodbox/x/beacon?id=1' -H 'Authorization: Bearer …' --data-raw '…'
```

The command is single-line for easy copy-paste and shell-safe (values are
single-quoted); `Content-Length` is dropped so curl recomputes it.

## Behaviour

- HTTP serves the bundled payload database (see `payload_db_seed.go`
  for the seeded set). Additional payloads can be loaded from a
  watched directory via `payload_dir`; changes are picked up via
  `fsnotify` and debounced into the database.
- HTTPS mode activates when `tls_names` is set; certmagic provisions
  certificates via ACME-DNS-01 against the configured `dns_provider`.
  Without `dns_provider`, HTTPS will fall back to HTTP-01 / TLS-ALPN
  challenges, which require port 80/443 reachability from the
  internet.
- Bot suppression: clients that exceed 30 requests in any one-minute
  bucket are marked as bots (`model.IsBot`) and have their subsequent
  events suppressed from notifier delivery (logged at `WARN`). The
  threshold itself is not configurable today. Loopback, RFC1918 private,
  and link-local sources are **exempt** from this suppression by default —
  they're usually the operator testing or an internal SSRF callback — so a
  burst of local/internal traffic won't silently mute your notifiers. Set
  `bot_exempt_private: "false"` to subject every source to bot detection.
- The private API (mounted at `api_path`) requires the header
  `Authorization: Token <api_token>` on every request. An empty
  `api_token` rejects all callers. **`api_token` is deprecated** in
  favour of the admin console's user accounts and API keys (see below);
  setting it logs a deprecation warning at start-up.
- Embedded static assets ship at `/ixdbxi/`.
- An embedded **admin web UI** (React SPA + JSON API) ships in the binary
  and is served under `ui_path` — or on a separate `admin_listener` bind —
  behind session/API-key auth and a CIDR allowlist (see below).

## Configuration

### General

| Key            | Required | Default | Notes                                                                                  |
|----------------|----------|---------|----------------------------------------------------------------------------------------|
| `handler`      | yes      | —       | Must be `HTTPX`.                                                                       |
| `listener`     | yes      | —       | Bind address, e.g. `:80` or `:8080`.                                                   |
| `static_dir`   | no       | —       | Directory served at `/static/`. Created on first start with mode `0750` if missing.    |
| `payload_dir`  | no       | —       | Directory of `*.md` payload definitions. Watched at runtime; updates are upserted.     |
| `api_path`     | no       | —       | URL path prefix to mount the JSON API on, e.g. `/api`. Normalised to leading/trailing slash. |
| `api_token`    | no       | —       | **Deprecated.** Bearer-style token for the legacy `/private/*` API. Prefer admin users + API keys. Setting it warns at start-up. |
| `bot_exempt_private` | no | `true` | Exempt loopback/private/link-local sources from volume-based bot suppression. Set to `"false"` to apply bot detection to every source. |
| `ui_path`      | no       | —       | URL path prefix to mount the admin web UI on, e.g. `/admin`. Empty disables it on the main listener. Normalised to leading/trailing slash. Ignored when `admin_listener` is set. |
| `ui_allow_cidrs` | no     | —       | Comma-separated CIDRs allowed to reach the admin UI/API, checked against the **real TCP peer IP** (never `X-Forwarded-For`). Empty allows any source (auth still required). Invalid entries are logged and ignored. |
| `admin_listener` | no     | —       | Separate bind address (e.g. `127.0.0.1:8443`) that serves **only** the admin UI/API, isolated from the attacker-facing listener. When set, the UI is not mounted under `ui_path` on the main listener. |
| `public_url`     | no     | —       | Externally-reachable base URL of the honeypot (e.g. `https://oob.example.com`). The admin UI's **Copy HTTP link** control on a sink builds `<public_url>/<slug>` from it. Empty falls back to the UI's own origin — correct when the UI is served on the honeypot listener, wrong on an isolated `admin_listener`. |
| `notify_logins`  | no     | `false` | When `"true"`, a successful admin-UI login emits an `InteractionEvent` (recorded in the Events log and delivered to notifiers whose filter matches `^HTTPX Login`). See **Login notifications** below. |
| `max_upload_size` | no    | `0`     | Per-file size cap for multipart/form-data uploads, in bytes. `0` means no limit. Files exceeding the cap are rejected with `413`. |

### OIDC / SSO

Optional single sign-on for the admin console via any OpenID Connect provider
(Google, Okta, Keycloak, Azure AD, Authentik, …). SSO runs **alongside** the
built-in username/password login — an "SSO" button appears on the login page
when `oidc_issuer` and `oidc_client_id` are set. See **OIDC single sign-on**
below.

| Key                  | Required | Default | Notes                                                                                  |
|----------------------|----------|---------|----------------------------------------------------------------------------------------|
| `oidc_issuer`        | no       | —       | Provider issuer URL. Setting this **and** `oidc_client_id` enables SSO. Discovery (`<issuer>/.well-known/openid-configuration`) is fetched lazily on the first login, so start-up never blocks on the IdP. |
| `oidc_client_id`     | no       | —       | OAuth2/OIDC client ID registered with the provider.                                    |
| `oidc_client_secret` | no       | —       | Client secret. Omit for public clients — the flow always uses Authorization Code + PKCE. |
| `oidc_redirect_url`  | no       | derived | Callback URL registered with the IdP, e.g. `https://oob.example.com/admin/api/auth/oidc/callback`. When empty it is derived from the request's scheme/host and admin mount path (honoring `X-Forwarded-Proto`). Set it explicitly when the console sits behind a proxy or on a non-obvious host. |
| `oidc_scopes`        | no       | `openid,profile,email` | Comma/space-separated scopes requested. `openid` is always included. |
| `oidc_default_role`  | no       | `user`  | Role assigned to provisioned users: `user` or `admin`.                                 |
| `oidc_groups_claim`  | no       | `groups`| ID-token claim inspected for group membership (may be a JSON array or a space/comma string). |
| `oidc_admin_group`   | no       | —       | When set, users whose `oidc_groups_claim` contains this value are granted the `admin` role; everyone else gets `oidc_default_role`. Empty means no group is elevated. |
| `oidc_button_label`  | no       | `Sign in with SSO` | Text shown on the login page's SSO button.                                |

### TLS / ACME

| Key                      | Required | Default | Notes                                                                                  |
|--------------------------|----------|---------|----------------------------------------------------------------------------------------|
| `tls_names`              | no       | —       | Comma-separated hostnames. Setting any value enables HTTPS via certmagic.              |
| `acme_email`             | no       | —       | ACME account contact address.                                                          |
| `acme_accept`            | no       | `false` | Must be the literal string `"true"` to accept the ACME provider's terms of service.    |
| `acme_url`               | no       | —       | ACME directory URL. Defaults to Let's Encrypt production; use the staging URL for testing. |
| `dns_provider`           | no       | —       | One of `namecheap` or `route53`. Required for the DNS-01 challenge path.               |
| `dns_provider_api_user`  | no       | —       | API user (namecheap only).                                                             |
| `dns_provider_api_key`   | no       | —       | API key (namecheap only).                                                              |

### MDaaS (Malicious Daemon as a Service) cross-compile

These keys are baked into binaries served from the `/build/<os>/<arch>/<program>`
route. Only useful when payloads request a build.

| Key                  | Required | Default | Notes                                                                                  |
|----------------------|----------|---------|----------------------------------------------------------------------------------------|
| `mdaas_log_level`    | no       | —       | One of `NONE`, `INFO`, `WARN`, `ERROR`, `DEBUG`.                                       |
| `mdaas_bind_listener`| no       | —       | Listener address baked into the built MDaaS binary.                                    |
| `mdaas_allowed_cidr` | no       | —       | CIDR allowed to connect to the built MDaaS binary at runtime.                          |
| `mdaas_notify_url`   | no       | —       | Webhook URL the built binary calls back to.                                            |

## Admin web UI

The binary embeds a responsive React admin console (built with Vite +
shadcn/ui, compiled into `pkg/handlers/httpx/webui/` via `//go:embed`) plus a
JSON admin API. It lets an operator log in and:

- view/edit/create/delete **payloads**,
- browse the **Events** log with filters (target, remote, handler) — the app
  persists interactions from **every** handler (httpx, dns, ftp, smtp, ssh, tcp,
  smb), so the log spans all protocols, not just HTTP,
- inspect an **event's detail** with a one-click **copy-as-curl**,
- get a **webhook-style view** of every hit to a specific `target` path,
- watch the **Events** log and **sink** feeds update in **real time** — new
  interactions stream in live via Server-Sent Events (`GET /api/stream`,
  filterable by `handler`/`remote`/`target`/`sink`), no refresh needed,
- manage **sinks** — named, described slugs with a per-slug event feed,
- review detected **bots**,
- manage **users** and **API keys**, and rotate their own password,
- edit the server **config** with a structured editor that shows labelled
  fields, descriptions, and grouped sections for each handler/notifier type
  — including a one-click **Enable OIDC / SSO** button that pre-populates
  all the SSO fields.

### Sinks

A **sink** is a named, described slug you embed in a payload (a URL path, a DNS
label, a query value) to correlate out-of-band interactions. Creating a sink
does not change what the honeypot captures — every path and name is already
recorded — it labels and groups the hits so you can remember what a slug is for
and review its whole feed in one place. An interaction belongs to a sink when
the slug appears in its `request_target` (HTTP path, DNS qname) or its raw
request headers (the request line + `Host`), so `/<slug>`, `<slug>.your.domain`,
and `?x=<slug>` all correlate. Deleting a sink leaves its captured interactions
untouched.

Sinks are managed in the UI (create with an optional slug + description, then
open one to see its events, newest first) and over the API — `GET/POST
/api/sinks`, `GET /api/sinks/{slug}` (sink + event feed), `DELETE
/api/sinks/{slug}`.

From the CLI (handy for scripting payload generation — only the slug is written
to stdout, so it is clean to capture):

```sh
SLUG=$(xodbox sink add --description "prod SSRF beacon")   # random slug
xodbox sink add my-label --description "a named one"        # explicit slug
xodbox sink list
xodbox sink rm my-label
```

Each sink's detail page has two copy controls: **Copy slug** (the bare slug, for
embedding in a payload) and **Copy HTTP link** (the full `<public_url>/<slug>`
URL a target would hit to land in the sink). Set `public_url` so the link points
at the honeypot's real address; without it the link uses the console's own
origin, which is only correct when the UI is mounted on the honeypot listener.

### Login notifications

Admin traffic normally produces no `InteractionEvent`s. With `notify_logins:
"true"`, each **successful** admin-UI login is an exception: it emits an event
so operators can be alerted when someone accesses the console. The event is
recorded in the Events log (as an `httpx` `LOGIN` interaction targeting the
username) and dispatched to notifiers. Its filter string has the canonical shape

```
HTTPX Login <username> from <ip>
```

so a notifier selects logins with a filter like `^HTTPX Login`. Failed login
attempts are **not** emitted (they are rate-limited and enumeration-resistant).

### Serving the console

Choose one of two mount strategies:

- **Same listener, sub-path:** set `ui_path` (e.g. `/admin`). The SPA and its
  `/api/*` routes are served under that prefix on the main HTTP(S) listener,
  with an SPA fallback for client-side routes.
- **Isolated listener (recommended):** set `admin_listener` (e.g.
  `127.0.0.1:8443`). The console binds there, fully separated from the
  attacker-facing port; `ui_path` is then ignored on the main listener.

Either way, access is gated by `ui_allow_cidrs` (evaluated against the real TCP
peer IP) **and** authentication. Admin routes never emit honeypot
`InteractionEvent`s.

### Authentication model

- **Browser sessions:** cookie-based, server-side session tokens (hashed at
  rest), `HttpOnly` + `SameSite=Strict` + `Secure` under TLS. State-changing
  requests require a double-submit **CSRF** token (`X-CSRF-Token` header echoing
  the `xodbox_csrf` cookie). Login is rate-limited and enumeration-resistant.
- **API keys:** send `Authorization: Bearer xdbx_…`. Keys are `sha256`-hashed at
  rest, compared in constant time, and shown in plaintext exactly once at
  creation. Bearer requests are CSRF-exempt.
- **Passwords:** bcrypt, 12-character minimum.
- **Roles:** `admin` (may manage users) and `user`.
- **OIDC/SSO:** optional; see below. SSO users authenticate against an external
  identity provider and never have a local password.

### OIDC single sign-on

When `oidc_issuer` and `oidc_client_id` are configured, the login page shows an
**SSO** button next to the password form (SSO and passwords coexist, so a
misconfigured IdP can't lock you out — a local admin can always sign in). The
flow is standard **Authorization Code + PKCE**:

1. The browser hits `/api/auth/oidc/login`, which stashes a `state`, `nonce`,
   and PKCE verifier in short-lived cookies and redirects to the provider.
2. The provider redirects back to `/api/auth/oidc/callback`, which validates
   `state`, exchanges the code (with the PKCE verifier), verifies the ID token
   signature and `nonce`, and then provisions the user and issues the **same**
   server-side session cookie the password flow uses. Everything downstream
   (CSRF, `requireAuth`, API keys) is unchanged.

**User provisioning is just-in-time.** On first login a local account is created
from the token's claims (no password, so it can never be used for password
login); the account is keyed by the token's `iss#sub`, never by email, so a
colliding email can't take over an existing account. On every login the user's
role is re-synced from the current claims, so IdP group changes take effect
immediately.

**Role mapping.** With `oidc_admin_group` set, a user whose `oidc_groups_claim`
contains that value gets the `admin` role; everyone else gets
`oidc_default_role` (default `user`). Manage further elevation from the **Users**
page as usual.

Example (Keycloak-style issuer):

```yaml
- handler: HTTPX
  listener: :80
  admin_listener: 127.0.0.1:9091
  public_url: https://oob.example.com
  oidc_issuer: https://sso.example.com/realms/corp
  oidc_client_id: xodbox
  oidc_client_secret: "…"
  oidc_redirect_url: https://oob.example.com/admin/api/auth/oidc/callback
  oidc_admin_group: xodbox-admins
```

### Bootstrapping users (CLI)

Create the first admin before starting the server (there is no default
account). API keys are then minted from the console.

```sh
xodbox user add alice --admin   # prints a generated password once
xodbox user list
xodbox user passwd alice        # reset a password (revokes active sessions)
xodbox user rm alice            # delete a user + their keys and sessions
```

### Example config

```yaml
handlers:
  - handler: HTTPX
    listener: ":80"
    admin_listener: "127.0.0.1:8443"   # console isolated from the honeypot port
    ui_allow_cidrs: "127.0.0.1/32,10.0.0.0/8"
    # ui_path: "/admin"                # alternative: same listener, sub-path
```

## Filters

The entire HTTP request (request line + headers + body) is fed to the
notifier filter regexps. To alert on a specific prefix:

```yaml
filter: "(GET|POST|HEAD|DELETE|PUT|PATCH|TRACE) /myPrefix"
```

This would match:

- `https://test.example/myPrefixexample`
- `https://test.example/myPrefix/example`
- `https://test.example/myPrefix/asdasd/asdasd/asd/as/d`

And would not match:

- `https://test.example/robots.txt`
- `https://test.example/asd/myPrefix/example`

## Operational notes

- `Stop(ctx)` shuts down whichever server pair Start booted: in HTTP
  mode, the single `*http.Server`; in HTTPS mode, both the ACME
  HTTP-01 challenge listener on :80 and the TLS listener on :443. The
  payload-directory watcher goroutine (if `payload_dir` was set) is
  also cancelled. ctx bounds how long in-flight requests have to
  drain. When `admin_listener` is set, its dedicated server is started
  in `Start` and shut down under the same `Stop(ctx)` drain.
- Sensitive operator keys (`api_token`, `dns_provider_api_key`) end up
  in the xodbox config file. Restrict that file's permissions to `0600`
  and the running user.
- Admin passwords, session tokens, and API keys live in the SQLite
  database (hashed), never in the config file. Prefer binding the admin
  console to an isolated `admin_listener` and/or a tight `ui_allow_cidrs`
  so it is never reachable from the attacker-facing port.

## Backlog

### New features

- [ ] Let's Encrypt Auto Cert
- [ ] Exfil data saver

### Legacy functionality to be implemented

- [x] robots.txt
- [x] unfurly
- [ ] arbitrary json
    - [ ] b64
- [x] redirect
    - [ ] b64
- [ ] basic auth
- [x] breakfastbot
- [ ] allow origin *

### Legacy functionality that isn't specific to a handler

- [ ] alert pattern with payload
- [ ] alert pattern (alert patterns are part of notifiers, maybe we need to expose alert patterns based on handler type)
- [ ] slack hook (this is now a notifier)
