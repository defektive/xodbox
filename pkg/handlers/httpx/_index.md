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

Support for HTTP request reflection in the following formats. Simply change the file extension in the request.

- [x] Plain Text (default, .txt)
- [x] HTML (.html, .html)
- [x] GIF (.gif)
- [x] JPEG (.jpg)
- [x] PNG (.png)
- [ ] MP4 (.mp4)
- [ ] XML (.xml)

#### New Features

- [ ] Let's Encrypt Auto Cert

#### Legacy Functionality

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

#### Legacy Payloads

slightly different then the original. Path must end with `/{original_pattern}`.

- [x] sh
- [x] dt
- [x] evil.dtd
- [x] ht
- [x] sv
