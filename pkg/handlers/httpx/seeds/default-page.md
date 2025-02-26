---
title: Default Page
description: Adds the default header to all HTTP responses.
weight: 9999
payloads:
  - sort_order: 9999
    pattern: ^/
    is_final: true
    data:
      headers:
        content-type: text/plain
      body: hi
---

Adds an HTTP header to all HTTP responses.

### Example Request

```shell
curl -i http://xodbox.test/
```

### Example Response

```txt
hi
```
