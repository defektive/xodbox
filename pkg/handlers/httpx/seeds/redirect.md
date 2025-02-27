---
title: Redirect
description: HTTP Redirects
weight: -900
pattern: ^/redir
is_final: true
data:
  status_code: "{{index .Request.GetParams.s 0}}"
  headers:
    Location: "{{index .Request.GetParams.l 0}}"
  body: so long!
---

HTTP Redirects to the query parameter `l` using the query param `s` as the status code.

| What     | Description             | GET Parameters |
|----------|-------------------------|----------------|
| Location | Location to redirect to | `l`            |
| Status   | HTTP status code        | `s`            |

### Example Request

```shell
curl -i "http://xodbox.test/redir?l=https://github.com/defektive/xodbox&s=301"
```

### Example Response

```txt
Location: https://github.com/defektive/xodbox
```
