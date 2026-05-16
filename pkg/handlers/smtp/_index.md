---
title: SMTP
description: SMTP Handler
weight: 10
---

{{% alert title="In development feature" %}}
This feature is in development. Please help make it awesome by providing feedback on your experience using it.
{{% /alert %}}

## Purpose

An SMTP listener that accepts (and then discards) mail to confirm
out-of-band email delivery from an application under test. Every
SMTP verb produces a separate `InteractionEvent` so MAIL FROM, RCPT
TO, DATA, RSET, AUTH PLAIN, and QUIT all show up in the dispatch
stream.

## Behaviour

- Backed by [`emersion/go-smtp`](https://github.com/emersion/go-smtp).
- `AllowInsecureAuth = true` — plaintext AUTH PLAIN is accepted on the
  cleartext socket; every attempt is recorded as a `PasswordAuth`
  event. **Do not point clients carrying real credentials at this
  handler.**
- A self-signed certificate is generated on startup for STARTTLS, with
  a randomised 128-bit serial and the SAN `test.com`. The certificate
  is intentionally untrusted (see [SECURITY.md](../../../SECURITY.md))
  — clients that accept it are the bug.
- The DATA body is read but discarded; only the action is dispatched.

## Configuration

| Key        | Required | Default | Notes                                                                          |
|------------|----------|---------|--------------------------------------------------------------------------------|
| `handler`  | yes      | —       | Must be `SMTP`.                                                                |
| `listener` | yes      | —       | Bind address, e.g. `:25`, `:587`, or `:1587` for unprivileged operation.       |

## Events

| Action         | Trigger                            |
|----------------|------------------------------------|
| `PasswordAuth` | Client issued AUTH PLAIN.          |
| `Mail`         | Client issued MAIL FROM.           |
| `Rcpt`         | Client issued RCPT TO.             |
| `Data`         | Client started DATA (body ignored).|
| `Reset`        | Client issued RSET.                |
| `Logout`       | Session ended (QUIT or connection close). |

## Operational notes

- `Stop(ctx)` calls `smtp.Server.Shutdown(ctx)`; in-flight sessions
  get the context's deadline to drain.
- The handler's `Debug` field is currently wired to `os.Stdout` —
  every SMTP exchange is echoed there in addition to being dispatched.
