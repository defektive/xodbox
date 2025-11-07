---
title: Remote Address Reflector
description: A restrictive robots.txt
weight: -900
pattern: ^/ip$
is_final: true
data:
  body: |
    {{range .Request.RemoteAddr -}}
    {{$ip :=  . -}}
    {{$parts := split ":" $ip -}}
    {{ $parts._0 }}
    {{ end -}}

---

Simple robots txt to prevent indexing.

### Example Request

```shell
curl http://xodbox.test/ip
```

### Example Response

```txt
10.1.2.3
```
