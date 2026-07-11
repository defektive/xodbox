---
title: xodbox
linkTitle: Docs
menu: {main: {weight: 20}}
---
> Network interaction listening post  
> [Docs](https://defektive.github.io/xodbox/) :: [Releases](https://github.com/defektive/xodbox/releases) :: [Code](https://github.com/defektive/xodbox/)  
> [![Go Tests](https://github.com/defektive/xodbox/actions/workflows/go-tests.yml/badge.svg)](https://github.com/defektive/xodbox/actions/workflows/go-tests.yml)

## Purpose

Quickly determine if an application reaches out to remote network based services. Easily create custom responses to test
how applications consume data from network sources.
* * *

## Features

Multiple listening protocols:

- [x] HTTP/HTTPS
- [x] DNS (in dev)
- [x] FTP (in dev)
- [x] SMTP (in dev)
- [x] SMB (in dev)
- [ ] IMAP
- [ ] POP3
- [x] SSH (in dev)
- [x] TCP (in dev)

Plus:

- An embedded **admin web console** (React SPA + JSON API) to browse the live
  event feed, edit payloads, group interactions into **sinks**, and manage users
  and API keys. Enable it with `ui_path` or an isolated `admin_listener` — see
  the [HTTPX handler docs](pkg/handlers/httpx).
- Pluggable **notifiers** (`app_log`, `slack`, `discord`, `webhook`) that fire on
  matching interactions, so a callback shows up in chat the moment it lands.

* * *

## Installation

Download a [release from GitHub](https://github.com/defektive/xodbox/releases) or use Go Install:

```sh
go install github.com/defektive/xodbox@latest
```
* * *

## Running without root (Linux)

Several handlers bind privileged ports (below 1024) by default — HTTP `:80`,
HTTPS `:443`, DNS `:53`, and SMB `:445`. Instead of running xodbox as root,
grant the binary the network capabilities it needs and run it as a normal user:

```sh
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip xodbox
./xodbox serve
```

`cap_net_bind_service` is what allows binding ports below 1024, and is the only
capability required for the current handlers; `cap_net_raw` and `cap_net_admin`
are included for forward compatibility and can be dropped if you don't need them.
Re-run `setcap` after upgrading — replacing the binary clears its capabilities.
* * *

## Configuration

```sh
./xodbox config -e > xodbox.yaml
```

### Handler Configuration

Configuration information for each Handler is documented alongside it's code in the [handlers](pkg/handlers) directory.

### Notifier Configuration

Configuration information for each Notifier is documented alongside it's code in the [notifiers](pkg/notifiers) directory.
* * *

## Server Usage

Start the listeners with the `serve` subcommand:

```sh
./xodbox serve
```

Running `./xodbox` with no subcommand prints the available commands (`serve`,
`config`, `payload`, `sink`, `user`, …). All the magic happens through the
configuration file — see the [handlers](pkg/handlers) and
[notifiers](pkg/notifiers) docs for what you can configure.

## Client Usage

When a client makes a connection to xodbox, the logic to respond will be processed by a [Handler](pkg/handlers). Handlers are responsible for seeding their own default data.

- [httpx/seeds/](pkg/handlers/httpx/seeds/)
* * *

## Quick Start Guides


### Linux

This little snippet will:
- Download and extract latest release from GitHub.
- Generate a new config file.
- create the static and payload directories used by the config file.

```sh
wget -q $(wget -q -O - https://api.github.com/repos/defektive/xodbox/releases/latest | grep -o "https:.*Linux_x86_64\.tar\.gz")
tar -xzvf xodbox*.tar.gz
./xodbox config -e | sed 's/^#\(\s*\(payload\|static\)_dir\)/ \1/g' > xodbox.yaml
mkdir -p static payloads/httpx
```

#### Bare metal

```shell
./xodbox serve 
```


#### Docker (prebuilt image from GHCR)

Prebuilt, [cosign](https://github.com/sigstore/cosign)-signed images are
published to GitHub Container Registry on every release. The image's entrypoint
is `xodbox` and its working directory is `/workspace`, so mount a directory
there to hold your config, database, and payloads, then pass a subcommand
(`serve`, `config`, `user`, …).

```sh
# 1. Generate a config into the current directory
docker run --rm -v "$PWD:/workspace" ghcr.io/defektive/xodbox:latest config -e > xodbox.yaml

# 2. Run the server (publish whatever ports your config listens on)
docker run --rm \
  -v "$PWD:/workspace" \
  --user "$(id -u):$(id -g)" \
  -p 80:80 \
  ghcr.io/defektive/xodbox:latest serve
```

The image runs as a non-root user. Passing `--user "$(id -u):$(id -g)"` makes it
read and write the mounted directory as *you*, so the config and SQLite database
stay owned by your host user. Pin a release tag (e.g.
`ghcr.io/defektive/xodbox:v1.2.3`) instead of `:latest` for reproducible deploys.

#### Docker (Alpine with a downloaded release)

Prefer not to pull the prebuilt image? The release binary is statically linked,
so you can run an extracted release inside a stock Alpine container. Run this
from the directory containing the extracted `xodbox` binary:

```shell
docker run \
  --rm \
  -p 80:80 \
  -v "$PWD:/app" \
  --workdir /app \
  alpine \
  ./xodbox serve
```


* * *

## Feedback

### I have an issue or feature request

Sweet! [Open an issue](https://github.com/defektive/xodbox/issues/new) to start the conversation.

* * *

## Wait... I want the old node version

Really? ok we made a tag just for you.

https://github.com/defektive/xodbox/releases/tag/legacy-nodejs

