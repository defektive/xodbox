---
title: XXE Callback
description: More XXE
weight: 1
pattern: /xxe-test$
is_final: true
data:
  headers:
    Content-Type: text/plain
  body: I should be loaded from http://{{ .Host }}/dt

---

XXE Callback used by xxe-system