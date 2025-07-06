---
title: Simple SSH Server
description: No password required! It's that simple....
weight: 10
---

{{% alert title="In development feature" %}}
This feature is in development. Please help make it awesome by providing feedback on your experience using it.
{{% /alert %}}

## Purpose

Quickly get SSH listening on a target machine.

## Configuration

None.

## Additional Information

Current port is `2222`. No auth :(.

## Roadmap

- [x] Add configure option for bind port
- [x] Add configure option for allowed CIDRs
- [ ] Add configuration option for some for of authentication


## Testing

Debug mode
```bash
go build -ldflags="-X main.listener=:8080 -X main.logLevel=DEBUG -X main.allowedCIDR=127.0.0.1/32" simple-ssh.go
```