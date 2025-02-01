---
title: HTTPX
description: HTTPX Handler
weight: 1
---

## Configuration


| Key                 | Values                                                                             |
|---------------------|------------------------------------------------------------------------------------|
| handler             | Must be `HTTPX`                                                                    |
| listener            | Default `:80`                                                                      |
| tls_domains         | Comma seperated list of domains                                                    |
| acme_staging        | Boolean. Shortcut to use `https://acme-staging-v02.api.letsencrypt.org/directory`  |
| acme_directory_url  | Override URL                                                                       |
| autocert_accept_tos | Boolean. Do you accept the CAs TOS?                                                |

## Responses

### Built-In

#### `/inspect`

Inspect or reflect the request back in various formats.

- [x] Plain Text (default, .txt)
- [x] HTML (.html, .html)
- [x] GIF (.gif)
- [x] JPEG (.jpg)
- [x] PNG (.png)
- [ ] MP4 (.mp4)
- [ ] XML (.xml)

##### Examples

- http://localhost/inspect
- http://localhost/some/random/path/inspect.gif

#### `/wpad.dat`

Returns a WPAD config file (Javascript).

#### `/sh`

Returns an XXE payload that attempt to get the contents of `/etc/hostname`.

#### `/dt`

Returns an XXE payload that attempts to load a xodbox URL as an external entitiy.

#### `/evil.dtd`

Returns a DTD that attempts to grab `/ets/passwd`.

#### `/js`

Returns a JavaScript payload that will embed an image that calls back to xodbox. 

#### `/ht`

Returns an HTML payload with an iframe source to `/etc/passwd`.

#### `/sv`

Returns an SVG payload with XXE to call back to xodbox.

#### New Features

- [ ] Let's Encrypt Auto Cert

#### Legacy Functionality to be implemented.

- [ ] robots.txt
- [ ] unfurly
- [ ] json
    - [ ] b64
- [ ] redirect
    - [ ] b64 
- [ ] alert pattern with payload
- [ ] alert pattern
- [ ] slack hook
- [ ] basic auth
- [ ] breakfastbot
- [ ] allow origin *

