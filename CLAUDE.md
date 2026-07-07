# CLAUDE.md

Guidance for working in this repository.

## What this is

**xodbox** is a network interaction listening post — a self-hosted out-of-band (OOB)
interaction server in the spirit of Burp Collaborator / interactsh. It listens on
multiple protocols and records/responds to inbound connections, so you can prove an
application reaches out to network services and craft custom responses to test how it
consumes remote data.

This is **authorized-pentest tooling**: a security tool for authorized engagements,
CTFs, and research. Generating payloads, shells, and OOB interaction primitives is the
point of the project and is in scope. Keep that framing when reasoning about changes.

Single Go binary (`xodbox`), Cobra CLI. Key subcommands: `serve` (run the listeners),
`config -e` (print the embedded default config), `payload` (manage payloads).

## Architecture

The flow is **Handlers → InteractionEvent → channel → Notifiers**.

- **Handlers** (`pkg/handlers/*`) are listening protocol implementations: `httpx`
  (HTTP/HTTPS, Gin-based), `dns`, `ftp`, `smtp`, `ssh`, `tcp`. Each implements
  `types.Handler` (`Name`/`Start`/`Stop`). `Start` blocks serving; `Stop(ctx)` must
  release the socket and be safe to call even if `Start` never ran.
- **InteractionEvent** (`pkg/types/interfaces.go`, base in `pkg/types/base_event.go`)
  is what a handler emits per inbound connection. It's pushed onto the app's event
  channel and dispatched to notifiers.
- **Notifiers** (`pkg/notifiers/*`): `app_log`, `slack`, `discord`, `webhook`. Each
  implements `types.Notifier` (`Name`/`Send`/`Filter`). A notifier only fires when the
  event matches its `Filter()` regex (default `^/l`).
- **App** (`pkg/xodbox/run.go`) wires it together: registers notifiers, seeds handlers,
  starts each handler in a goroutine, and fans events out to notifiers. Graceful
  shutdown on SIGINT/SIGTERM with a bounded drain timeout.
- **Config** (`pkg/xodbox/config.go`): `ConfigFile` (YAML) → `Config`. Handlers and
  notifiers are looked up by name in `newHandlerMap` / `newNotifierMap`.
- `pkg/model` — GORM + SQLite persistence (interactions, payloads, projects).
- `pkg/mdaas` — payload/binary builder ("malicious delivery as a service"): cross-OS/arch
  target translation and Go build orchestration. `pkg/handlers/httpx` ties into it for
  payload serving.

Config-first: behavior is driven by `xodbox.yaml`, not hardcoded. Generate a starting
config with `xodbox config -e > xodbox.yaml`. Prefer adding configurable knobs over
hardcoding values that belong in config.

## Dev workflow

Use the Makefile (`make help` lists targets). Before considering a change done / before
committing, all of these must pass:

```sh
make fmt      # gofmt -s -w over the repo
make lint     # golangci-lint (mirrors .golangci.yml + CI reviewdog)
make test     # go test ./... (use `make race` for the race detector)
make tidy     # go mod tidy must leave go.mod/go.sum unchanged
```

Other targets: `make build` (→ `./bin/xodbox`), `make run` (build + serve), `make cover`,
`make release-dry` (goreleaser snapshot).

## Conventions

When **adding a Handler or Notifier**:

1. **Register it** in `newHandlerMap` / `newNotifierMap` in `pkg/xodbox/config.go` so the
   YAML config can reference it by name.
2. **Write docs**: add/update the Hugo `_index.md` for the package (see existing
   `pkg/handlers/*/_index.md`). These feed the docs site — see below.
3. If it populates DB state, implement `types.Seeder` and make `Seed()` **idempotent**
   (the app calls it exactly once before any handler starts; `httpx` payload seeding is
   the reference example).
4. Follow the package-local **`logging.go`** pattern — each package defines a `lg()`
   helper (`pkg/xlog` is the shared slog setup). Don't log via `fmt`/global loggers.

## Docs are Hugo

Markdown across the repo (`_index.md`, README frontmatter under `.hugo/`) feeds a
Hugo / GitHub Pages site (https://defektive.github.io/xodbox/). The YAML frontmatter
matters — keep it intact when editing docs, and document new handlers/notifiers there.

## Notes

- `cmd/xodbox-validator/` is its own **separate Go module** (its own `go.mod`); it is not
  part of the root module's build.
