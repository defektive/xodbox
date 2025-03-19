---
title: Notifiers
description: Interaction notifiers
weight: 10
---

Notifiers are used to send notifications to external services or log interactions to the app log.

### Filters

Each notifier will accept a `filter` configuration option. This option will be compiled into a golang regexp object. What it is executed against depends on the event it is executing against. For HTTPX events it will be the entire HTTP request. This would be a simple example of matching a specific path prefix `(GET|POST|HEAD|DELETE|PUT|PATCH|TRACE) /x/`.

Be sure to check each [handler](../handlers) for mor information on what it's event supplies for filter matching.
