---
title: Bind Shell
description: Stupid Simple Bind Shell
weight: 10
---

{{% alert title="In development feature" %}}
This feature is in development. Please help make it awesome by providing feedback on your experience using it.
{{% /alert %}}

## Purpose

Bind to a port and serve a shell to clients

## Configuration

None.

## Additional Information

Current port is `4444`. No auth :(.

## Roadmap

- [x] Add configure option for bind port
- [x] Add configure option for allowed CIDRs
- [ ] Add configuration option for some for of authentication

## Testing

Debug mode
```bash
go build -ldflags="-X main.listener=:8080 -X main.logLevel=DEBUG -X main.allowedCIDR=127.0.0.1/32" bind-shell.go
```