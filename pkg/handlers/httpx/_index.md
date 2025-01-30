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

