---
title: List Payloads
description: List payloads
weight: 1
pattern: /i-forgot-how-things-work$
is_final: true
data:
  headers:
    Content-Type: text/plain
  body: |
    Payloads
    
    {{ range .Payloads }}
    {{ .Pattern }} - {{ .Name }} [{{ .Type }}]
    {{ .Description }}
    
    {{ end }}
    

---

List Payloods

```yaml
---
title: List Payloads
description: List payloads
weight: 1
pattern: /i-forgot-how-things-work$
is_final: true
data:
  headers:
    Content-Type: text/plain
  body: |
    Payloads
    
    {{ range .Payloads }}
    {{ .Pattern }} - {{ .Name }} [{{ .Type }}]
    {{ .Description }}
    
    {{ end }}
---
```