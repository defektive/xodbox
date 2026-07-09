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
  events suppressed from notifier delivery. The bot threshold is not
  configurable today.
- The private API (mounted at `api_path`) requires the header
  `Authorization: Token <api_token>` on every request. An empty
  `api_token` rejects all callers.
- Embedded static assets ship at `/ixdbxi/`.

## Configuration

### General

| Key            | Required | Default | Notes                                                                                  |
|----------------|----------|---------|----------------------------------------------------------------------------------------|
| `handler`      | yes      | —       | Must be `HTTPX`.                                                                       |
| `listener`     | yes      | —       | Bind address, e.g. `:80` or `:8080`.                                                   |
| `static_dir`   | no       | —       | Directory served at `/static/`. Created on first start with mode `0750` if missing.    |
| `payload_dir`  | no       | —       | Directory of `*.md` payload definitions. Watched at runtime; updates are upserted.     |
| `api_path`     | no       | —       | URL path prefix to mount the JSON API on, e.g. `/api`. Normalised to leading/trailing slash. |
| `api_token`    | no       | —       | Bearer-style token required by the `/private/*` API routes.                            |

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
  drain.
- Sensitive operator keys (`api_token`, `dns_provider_api_key`) end up
  in the xodbox config file. Restrict that file's permissions to `0600`
  and the running user.

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
