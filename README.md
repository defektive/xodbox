---
title: xodbox
linkTitle: Docs
menu: {main: {weight: 20}}
---
> Network interaction listening post
> https://defektive.github.io/xodbox/

## Purpose

Quickly determine if an application reaches out to remote network based services. Easily create custom responses to test
how applications consume data from network sources.

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

## Installation

Download a [release from GitHub](https://github.com/defektive/xodbox/releases) or use Go Install:

```sh
go install github.com/defektive/xodbox@latest
```

## Configuration

```sh
cp example.xodbox.yaml xodbox.yaml
```

### Handler Configuration

Configuration information for each HAndler is documented alongside it's code in the [handlers](pkg/handlers) directory.

### Notifier Configuration

Configuration information for each Notifier is documented alongside it's code in the [notifiers](pkg/notifiers) directory.

## Server Usage

```sh
./xodbox
```

## Client Usage

[Handlers](pkg/handlers) are responsible for seeding their own default data.

- [httpx/seeds/](pkg/handlers/httpx/seeds/)


## Feedback

### I have an issue or feature request

Sweet! [Open an issue](https://github.com/defektive/xodbox/issues/new) to start the conversation.

* * *

## Wait... I want the old node version

Really? ok we made a tag just for you.

https://github.com/defektive/xodbox/releases/tag/legacy-nodejs