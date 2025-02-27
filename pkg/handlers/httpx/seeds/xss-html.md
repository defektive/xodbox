---
title: XSS HTML
description: Returns HTML that embeds xss-js
weight: -500
pattern: /jsc.html$
is_final: true
data: 
  headers:
    "Content-Type": "text/html"
  body: |
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
      </head>
      <body>
        <script src="//{{.Host}}/jsc"></script>
      </body>
    </html>

---

### /jsc.html

Simple HTML to load simple JS Payload.

