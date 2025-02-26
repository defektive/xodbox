---
title: Default Favicon
description: Redirects to the default logo.
weight: -1
payloads:
  - sort_order: -1
    pattern: favicon\.ico
    data:
      status_code: 301
      headers:
        Location: /ixdbxi/default-logo.svg
---

Redirects to the embedded default logo, exposed via embedded fs.

### Example Request

```shell
curl -i http://xodbox.test/favicon.ico
```

