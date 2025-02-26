---
title: HTTPX
description: HTTPX Handler
weight: 10
---

## Purpose

Speak HTTP to other computers you may or may not control....


## Configuration

| Key                 | Values                                                                            |
|---------------------|-----------------------------------------------------------------------------------|
| handler             | Must be `HTTPX`                                                                   |
| listener            | Default `:80`                                                                     |
| static_dir          | Directory to host static files from                                               |


### WIP configs that are not fully implemented

| Key                 | Values                                                                            |
|---------------------|-----------------------------------------------------------------------------------|
| tls_domains         | Comma seperated list of domains                                                   |
| acme_staging        | Boolean. Shortcut to use `https://acme-staging-v02.api.letsencrypt.org/directory` |
| acme_directory_url  | Override URL                                                                      |
| autocert_accept_tos | Boolean. Do you accept the CAs TOS?                                               |


## Additional Information

Things are still being created, documented, and fine-tuned.

### New Features

- [ ] Let's Encrypt Auto Cert
- [ ] Exfil data saver

#### Legacy Functionality to be implemented.

- [x] robots.txt
- [x] unfurly
- [ ] arbitrary json
    - [ ] b64
- [x] redirect
    - [ ] b64 
- [ ] basic auth
- [x] breakfastbot
- [ ] allow origin *

#### Legacy functionality that isnt specific to a handler

- [ ] alert pattern with payload
- [ ] alert pattern (alert patterns are part of notifiers, maybe we need to expose alert patterns based on handler type)
- [ ] slack hook (this is now a notifier)
