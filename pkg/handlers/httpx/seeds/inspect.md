---
title: Inspect
description: Reflect back HTTP requests in various formats
weight: -500
pattern: /inspect
internal_function: inspect
is_final: true
data:
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

Depends on an internal code

### `/inspect`

Inspect or reflect the request back in various formats.

- [x] Plain Text (default, .txt)
- [x] HTML (.html, .html)
- [x] GIF (.gif)
- [x] JPEG (.jpg)
- [x] PNG (.png)
- [ ] MP4 (.mp4)
- [x] XML (.xml)
- [x] JSON (.json)
- [x] Javascript (.js)

### Examples

- http://localhost/inspect
- http://localhost/some/random/path/inspect.gif
