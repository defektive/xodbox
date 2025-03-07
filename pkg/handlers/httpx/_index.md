---
title: HTTPX
description: HTTPX Handler
weight: 10
---

## Purpose

Speak HTTP to other computers you may or may not control....

## Configuration

| Key                   | Values                                                                                                                                                                                                                                                        |
|-----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| handler               | Must be `HTTPX`                                                                                                                                                                                                                                               |
| listener              | Default `:80`                                                                                                                                                                                                                                                 |
| static_dir            | Directory to host static files from                                                                                                                                                                                                                           |
| payload_dir           | Directory to import payloads from                                                                                                                                                                                                                             |
| acme_email            | Email to use for your ACME account                                                                                                                                                                                                                            |
| acme_accept           | A dumb way to force you to ensure you agree to the ACME provider's (Most likely Let's Encrypt) TOS                                                                                                                                                            |
| acme_url              | https://acme-staging-v02.api.letsencrypt.org/directory, https://acme-v02.api.letsencrypt.org/directory, or one of these: [Certmagic acmeissuer.go](https://github.com/caddyserver/certmagic/blob/54e6486cea81c9014aaeaf74094b11887bd5ef15/acmeissuer.go#L653) |
| tls_names             | Your domains to get TLS certificates for comma separated. I had to do wildcards first, not sure if that was a staging or dns provider issue.                                                                                                                  |
| dns_provider          | Currently, `namecheap` or `route53` but we *can* support anything [libdns](https://github.com/libdns) supports...                                                                                                                                             |
| dns_provider_api_user | Username for API calls. Only used for namecheap ATM.                                                                                                                                                                                                          |
| dns_provider_api_key  | Key for API calls. Only used for namecheap ATM.                                                                                                                                                                                                               |


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
