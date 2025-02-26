---
title: Robots TXT
description: Adds the default header to all HTTP responses.
weight: -900
payloads:
  - sort_order: -900
    pattern: ^/robots\.txt
    data:
      body: "User-agent: *\nDisallow: /\n"
---

Simple robots txt to prevent indexing.

### Example Request

```shell
curl http://xodbox.test/robots.txt
```

### Example Response

```txt
User-Agent: *
Disallow: /
```
