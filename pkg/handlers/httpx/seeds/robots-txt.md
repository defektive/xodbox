---
title: Robots TXT
description: A restrictive robots.txt
weight: -900
pattern: ^/robots\.txt
is_final: true
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
