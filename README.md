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
- [ ] DNS (WIP not finished)
- [ ] FTP
- [ ] SMTP
- [ ] SMB
- [ ] IMAP
- [ ] POP3
- [ ] SSH

* * *

## Installation

Download a [release from GitHub](https://github.com/defektive/xodbox/releases) or use Go Install:

```sh
go install github.com/defektive/xodbox@latest
```
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

```sh
./xodbox
```

All the magic happens through configuration files in the [handlers](pkg/handlers) and [notifiers](pkg/notifiers).

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

#### Docker

Currently, we do not have any prebuilt Docker containers. However, you can just run a release with an Alpine container.

```shell
docker run \
  --rm \
  --expose 80 \
  -v `pwd`:/app \
  --workdir /app \
  -d alpine \
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