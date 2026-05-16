---
title: TCP
description: TCP Handler
weight: 10
---

{{% alert title="In development feature" %}}
This feature is in development. Please help make it awesome by providing feedback on your experience using it.
{{% /alert %}}

## Purpose

A raw TCP listener that accepts every connection, reads anything the
client sends, and emits an event per chunk. Useful for confirming
out-of-band TCP reach-out from an application under test where the
client doesn't speak a recognised application protocol.

## Behaviour

- Listens on `tcp4` at the configured `listener` address.
- One `Connect` event per accepted connection.
- One `DataRecv` event per `read()` call from the client, carrying the
  bytes that were actually read in `RawData` (`Data()`). Chunks are
  copied before dispatch — slices are safe to retain across the
  channel.
- One `Disconnect` event when the read loop exits (EOF, peer reset,
  read error, or `Stop()`).
- The handler never writes back to the client.

## Configuration

| Key        | Required | Default | Notes                                                                          |
|------------|----------|---------|--------------------------------------------------------------------------------|
| `handler`  | yes      | —       | Must be `TCP`.                                                                 |
| `listener` | yes      | —       | Bind address, e.g. `127.0.0.1:9090`. IPv6-only binds are not currently supported. |

## Events

| Action       | Trigger                                                  | Data payload         |
|--------------|----------------------------------------------------------|----------------------|
| `Connect`    | Accepted a new connection.                               | none                 |
| `DataRecv`   | Bytes received from the client.                          | the chunk just read  |
| `Disconnect` | Read loop exited (EOF, error, or Stop).                  | none                 |

## Operational notes

- The accept loop returns from `Start()` cleanly when `Stop()` closes
  the listener. In-flight `handleConn` goroutines drain naturally as
  their peers close.
- `Stop(ctx)` ignores the context's deadline — closing the listener is
  immediate.
