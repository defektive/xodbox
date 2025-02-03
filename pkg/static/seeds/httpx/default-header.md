---
title: Default Header
description: Adds the default header to all HTTP responses
weight: 1
payloads:
  - type: HTTPX
    project_id: 1
    sort_order: -1000
    pattern: ^/
    data: '{"headers":{"Server":"BreakfastBot/1.0.0"},"body":""}'
---

Adds a HTTP header to all HTTP responses.

### Example

```txt
Server: BreakfastBot/1.0.0
```

### Usage

Visit any endpoint.