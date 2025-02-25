---
title: Redirect
description: HTTP Redirects
weight: -900
payloads:
  - type: HTTPX
    sort_order: -900
    pattern: ^/redir
    data:
        status_code: "{{.GET_s}}"
        headers:
            Location: "{{.GET_l}}"
        body: "so long!"
---

HTTP Redirects

### Example Request

```shell
curl -i "http://xodbox.test/redir?l=https://github.com/defektive/xodbox&s=301"
```

### Example Response

```txt
Location: ....
```
