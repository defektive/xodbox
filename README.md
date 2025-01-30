---
title: XodBox
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

#### DNS

| Key        | Values                                                                        |
|------------|-------------------------------------------------------------------------------|
| handler    | Must be `DNS`                                                                 |
| listener   | Default `:53`                                                                 |
| default_ip | An IP address default will be whatever is detected as the server's public IP. |

#### HTTPX

| Key      | Values                                                                       |
|----------|------------------------------------------------------------------------------|
| handler | Must be `HTTPX`                                                              |
| listener | Default `:80`                                                                |
| autocert | Boolean. Determines if a TLS cert should be auto created using Let's Encrypt |

### Notifier Configuration

#### Log

| Key      | Values                                                                       |
|----------|------------------------------------------------------------------------------|
| notifier | Must be `log`                                                                |

#### Slack

| Key          | Values                                             |
|--------------|----------------------------------------------------|
| notifier     | Must be `slack`                                    |
| url          | Webhook URL                                        |
| author       | Username to appear in slack. (optional)            |
| author_image | Emoji code to use for user's avatar. (optional)    |
| channel      | Channel to post to, can be a user's ID. (optional) |

#### Discord

| Key          | Values                                          |
|--------------|-------------------------------------------------|
| notifier     | Must be `slack`                                 |
| url          | Webhook URL                                     |
| author       | Username to appear in slack. (optional)         |
| author_image | Emoji code to use for user's avatar. (optional) |

## Usage

```sh
./xodbox
```