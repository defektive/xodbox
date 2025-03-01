---
title: HTTPX
description: HTTPX Handler
weight: 10
---

## Purpose

Speak HTTP to other computers you may or may not control....


## Configuration

| Key                   | Values                                                                             |
|-----------------------|------------------------------------------------------------------------------------|
| handler               | Must be `HTTPX`                                                                    |
| listener              | Default `:80`                                                                      |
| static_dir            | Directory to host static files from                                                |
| payload_dir           | Directory to import payloads from                                                  |
| domains               | Comma seperated list of domains                                                    |
| cert_cache_dir        | directory to cache cert information in                                             |
| cert_email            | email to use for let's encrypt requests                                            |
| acme_staging          | Boolean. Shortcut to use `https://acme-staging-v02.api.letsencrypt.org/directory`  |
| acme_dir_url          | ACME Directory URL                                                                 |
| cert_dns_provider     | DNS provider for DNS challenges. see: https://go-acme.github.io/lego/dns/          |
| cert_dns_provider_env | ENV vars required for DNS challenge providers                                      |


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
