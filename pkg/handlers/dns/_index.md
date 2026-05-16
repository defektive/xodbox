---
title: DNS
description: DNS Handler
weight: 10
---

{{% alert title="In development feature" %}}
This feature is in development. Please help make it awesome by providing feedback on your experience using it.
{{% /alert %}}

## Purpose

A DNS UDP listener that records every query it receives and answers
each one with a single A record. Useful for confirming out-of-band DNS
resolution from an application under test (e.g. SSRF, XXE, log4shell
flavoured probes).

## Behaviour

- Listens on UDP at the configured `listener` address.
- For each incoming query, dispatches an `InteractionEvent` whose
  `Details()` reports the first non-empty question name.
- Replies with an `A` record pointing every name to `default_ip`,
  regardless of the requested type. Non-A queries still receive the
  forged A reply.
- A future enhancement may store per-name records in the database;
  today the handler is intentionally a single-answer reflector.

## Configuration

| Key          | Required | Default | Notes                                                                                  |
|--------------|----------|---------|----------------------------------------------------------------------------------------|
| `handler`    | yes      | —       | Must be `DNS`.                                                                         |
| `listener`   | yes      | —       | Bind address, e.g. `:53` or `0.0.0.0:5353`. Requires `CAP_NET_BIND_SERVICE` for port 53.|
| `default_ip` | yes      | —       | IPv4 string returned as the A record for every query. Invalid values yield empty responses. |

## Operational notes

- The handler responds to every query, including ANY/AAAA/MX. Use a
  filter at the notifier layer if you only care about specific names.
- `Stop()` shuts the underlying `*dns.Server` down with the supplied
  context as the drain deadline.
