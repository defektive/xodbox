---
title: DNS
description: DNS Handler
weight: 10
---

{{% alert title="In development feature" %}}
This feature is in development. Please help make it awesome by providing feedback on your experience using it.
{{% /alert %}}

## Purpose

Currently, this handler just returns a single IP address for every request. In the future, I'd like to be able to force specific DNS responses. Most should be possible using the subdomain. However, I think it would be easier to store records in the DB or config.

## Configuration

| Key        | Values                                                                        |
|------------|-------------------------------------------------------------------------------|
| handler    | Must be `DNS`                                                                 |
| listener   | Default `:53`                                                                 |
| default_ip | An IP address default will be whatever is detected as the server's public IP. |

