# xodbox
Network interaction handler

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

Payloads

- [ ] XML XXE
- [ ] JS XSS callback

Notifiers

- [x] Text Log
- [ ] JSON Log
- [ ] Slack Webhook
- [ ] Discord Webhook
- [ ] Keybase Webhook

## Installation

Download a [release from GitHub](https://github.com/defektive/xodbox/releases) or use Go Install:

```sh
go install github.com/defektive/xodbox@latest
```

## Usage

```sh
./xodbox
```