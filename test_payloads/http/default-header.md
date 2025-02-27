---
title: Default Header
description: Adds the default header to all HTTP responses.
weight: -1000
payloads:
  - sort_order: -1000
    pattern: ^/
    data:
      headers:
        Server: BradBot/420
---

Adds an HTTP header to all HTTP responses.

### Example Request

```shell
curl -i http://xodbox.test/
```

### Example Response

```txt
Server: BradBot/1.0.0
```
