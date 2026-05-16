---
title: SSH
description: SSH Handler
weight: 10
---

{{% alert title="In development feature" %}}
This feature is in development. Please help make it awesome by providing feedback on your experience using it.
{{% /alert %}}

## Purpose

An SSH listener that records every authentication attempt and then
rejects it. Useful for credential-stuffing telemetry and for
confirming out-of-band SSH reach-out from an application under test.

## Behaviour

- Backed by [`gliderlabs/ssh`](https://github.com/gliderlabs/ssh).
- Both password and public-key auth callbacks dispatch an
  `InteractionEvent` (`PasswordAuth` / `KeyAuth`) carrying the
  attempting username and remote address. Both callbacks then return
  `false`, so no session is ever established.
- If a session were to open (it does not, by design), it would write
  `"This account is currently not available\n"` and close.
- A fresh host key is generated on first startup. The handler does
  not currently expose host-key configuration.

## Configuration

| Key        | Required | Default | Notes                                                                          |
|------------|----------|---------|--------------------------------------------------------------------------------|
| `handler`  | yes      | —       | Must be `SSH`.                                                                 |
| `listener` | no       | `:22`   | Bind address. Use `:2222` to avoid `CAP_NET_BIND_SERVICE`.                     |

## Events

| Action         | Trigger                                                        |
|----------------|----------------------------------------------------------------|
| `PasswordAuth` | Client offered `username:password`. Submitted password is logged at debug. |
| `KeyAuth`      | Client offered a public key. Key type is logged at debug.       |

## Operational notes

- Every credential attempt that lands here is logged. Plaintext
  passwords reaching the handler should be treated as compromised.
- `Stop(ctx)` calls `ssh.Server.Shutdown(ctx)`.
