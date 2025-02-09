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
- [x] DNS
- [ ] FTP
- [ ] SMTP
- [ ] SMB
- [ ] IMAP
- [ ] POP3
- [ ] SSH

Payloads

- [ ] XML XXE
- [ ] JS XSS callback

Notifiers

- [x] Text Log
- [ ] JSON Log
- [X] Slack Webhook
- [X] Discord Webhook
- [ ] Keybase Webhook

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

## Usage

```sh
./xodbox
```

## Refactor / Migration Tracking

- [ ] Tag existing branch
- [ ] rename master to main
- [ ] Configure github actions to build doc site
- [ ] Configure github actions to run goreleaser
- [ ] Remove files
  - [ ] Makefile
  - [ ] example*env
  - [ ] server.js
- [ ] PocketBase for admin
- [ ] Docs
  - [ ] Validator
  - [ ] HTTPx Handler
  - [ ] DNS Handler
  - [ ] How To Make A Handler
  - [ ] Slack Notifier
  - [ ] Discord Notifier
  - [ ] Log Notifier
  - [ ] ???
- [ ] Seeds from Markdown
