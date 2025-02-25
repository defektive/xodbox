---
title: Inspect
description: Reflect back HTTP requests in various formats
weight: 1
payloads:
  - type: HTTPX
    sort_order: -500
    pattern: /inspect
    internal_function: inspect
---

Depends on an internal code


#### `/inspect`

Inspect or reflect the request back in various formats.

- [x] Plain Text (default, .txt)
- [x] HTML (.html, .html)
- [x] GIF (.gif)
- [x] JPEG (.jpg)
- [x] PNG (.png)
- [ ] MP4 (.mp4)
- [ ] XML (.xml)

##### Examples

- http://localhost/inspect
- http://localhost/some/random/path/inspect.gif
