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
    curl {{.Request.Host}}/l/$OS/$ARCH
---
