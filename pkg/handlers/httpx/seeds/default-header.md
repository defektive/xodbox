---
title: Default Header
description: Adds the default header to all HTTP responses.
weight: -1000
payloads:
  - type: HTTPX
    sort_order: -1000
    pattern: ^/
    data:
        headers:
            Server: "BreakfastBot/{{.Version}}"
---

Adds an HTTP header to all HTTP responses.

### Example Request

```shell
curl -i http://xodbox.test/
```

### Example Response

```txt
Server: BreakfastBot/1.0.0
```
