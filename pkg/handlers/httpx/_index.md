---
title: HTTPX
description: HTTPX Handler
weight: 1
---

## Purpose

Speak HTTP to other computers you may or may not control....


## Configuration

| Key                 | Values                                                                             |
|---------------------|------------------------------------------------------------------------------------|
| handler             | Must be `HTTPX`                                                                    |
| listener            | Default `:80`                                                                      |
| tls_domains         | Comma seperated list of domains                                                    |
| acme_staging        | Boolean. Shortcut to use `https://acme-staging-v02.api.letsencrypt.org/directory`  |
| acme_directory_url  | Override URL                                                                       |
| autocert_accept_tos | Boolean. Do you accept the CAs TOS?                                                |


## Additional Information

Things are still being created, documented, and fine-tuned.

### New Features

- [ ] Let's Encrypt Auto Cert

#### Legacy Functionality to be implemented.

- [x] robots.txt
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



response.setHeader('Content-Type', 'text/html')
response.end([
`<html><head>`,
`<meta property="og:title" content="Unfurly" />`,
`<meta property="og:description" content="${userAgent}" />`,
//`<meta name="twitter:image:src" value="" />`,
`<meta name="twitter:label1" value="IP Address" />`,
`<meta name="twitter:data1" value="${remoteAddr}" />`,
`<meta name="twitter:label2" value="" />`,
`<meta name="twitter:data2" value="" />`,
`</head><body>`,
`</body></html>`,
].join("\n"))