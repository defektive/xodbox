---
title: Open Graph
description: Embed request params in open graph elements.
weight: 1
pattern: ^/unfurl
is_final: true
data:
  body: |
    <html>
    <head>
      <meta property="og:title" content="Unfurly" />
      <meta property="og:description" content="{{.UserAgent}}" />
      <meta name="twitter:image:src" value="{{.CallBackImageURL}}" />
      <meta name="twitter:label1" value="IP Address" />
      <meta name="twitter:data1" value="{{.RemoteAddr}}" />
      <meta name="twitter:label2" value="" />
      <meta name="twitter:data2" value="" />
    </head>
    <body></body>
    </html>
---

Useful for unfurlers. Maybe we should merge this into inspect...

### Example Request

```shell
curl -i "http://xodbox.test/unfurl"
```

### Example Response

```txt
Location: https://github.com/defektive/xodbox
```
