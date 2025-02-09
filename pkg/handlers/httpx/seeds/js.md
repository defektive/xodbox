---
title: Inspect
description: Reflect back HTTP requests in various formats
weight: 1
payloads:
  - type: HTTPX
    project_id: 1
    sort_order: 1
    pattern: /js$
    data: '{"headers":{"Content-Type":"text/javascript"},"body":"var s = document.createElement(\"img\");document.body.appendChild(s); s.src=\"//{{ .Host }}/{{.AlertPattern}}/s\";"}'
---

Depends on an internal code