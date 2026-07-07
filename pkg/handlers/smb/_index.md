---
title: SMB
description: SMB Handler (NetNTLMv2 capture)
weight: 10
---

{{% alert title="In development feature" %}}
This feature is in development. Please help make it awesome by providing feedback on your experience using it.
{{% /alert %}}

## Purpose

A fake SMB server for authorized engagements. It speaks just enough SMB2
to walk a client through NTLM authentication and capture the resulting
**NetNTLMv2** response as a hashcat-crackable hash. Point a target at
`\\your-host\share` (via a coerced UNC path, `img src=file://…`,
`RESPONDER`-style poisoning, an SSRF, etc.) and, if it authenticates, you
get its hash.

It never grants a session — every authentication attempt is answered with
a logon failure once the hash has been recorded. No credentials are
verified and no shares are served.

## Behaviour

- Listens on `tcp4` at the configured `listener` address (SMB direct-host,
  default `:445`).
- Answers a legacy SMB1 multi-protocol negotiate with an SMB2 wildcard so
  the client re-negotiates over SMB2; answers SMB2 `NEGOTIATE` with dialect
  `2.1` and a SPNEGO token advertising NTLMSSP.
- On `SESSION_SETUP`, returns an NTLMSSP **CHALLENGE** with the fixed
  server challenge `0x1122334455667788` (the Responder/Impacket
  convention, so captured hashes work with existing tooling).
- Parses the client's NTLMSSP **AUTHENTICATE**, extracts the domain, user
  and NT challenge response, and emits an `Auth` event whose `Data()` is
  the hashcat **mode 5600** line:

  ```
  user::domain:1122334455667788:<NTProofStr>:<clientBlob>
  ```

- Answers the authenticate with `STATUS_LOGON_FAILURE` and closes.

## Configuration

| Key        | Required | Default | Notes                                                        |
|------------|----------|---------|--------------------------------------------------------------|
| `handler`  | yes      | —       | Must be `SMB`.                                                |
| `listener` | no       | `:445`  | Bind address. Binding `:445` usually needs elevated privileges. |
| `persist`  | no       | `false` | Must be the literal string `"true"` to save captured hashes to the database (the `interactions` table). Off by default because captured NetNTLMv2 hashes are crackable credential material sitting on disk. |

## Events

| Action       | Trigger                                             | Data payload                          |
|--------------|-----------------------------------------------------|---------------------------------------|
| `Connect`    | Accepted a new connection.                          | none                                  |
| `Negotiate`  | First SMB2 `NEGOTIATE` seen on the connection.      | none                                  |
| `Auth`       | Client sent an NTLMSSP AUTHENTICATE.                | NetNTLMv2 hash (hashcat mode 5600)    |
| `Disconnect` | The exchange ended (EOF, error, or `Stop()`).       | none                                  |

Feed a captured `Auth` payload straight to `hashcat -m 5600` or
`john --format=netntlmv2`.

With `persist: true`, each `Auth` capture is also written to the
`interactions` table (`handler=smb`, `request_type=Auth`), with the
`DOMAIN\User` in `request_target` and the hashcat line in `data`, so it
survives restarts and appears in the web view.

## Operational notes

- Only NTLMv2 is captured. LM-only / NTLMv1 clients (rare, and usually
  disabled) are logged and skipped.
- The advertised target name is the cosmetic constant `XODBOX`; it only
  affects what the client believes it connected to.
- No SMB library is vendored — the minimal SMB2/NTLMSSP/SPNEGO wire format
  is implemented in-package, so the handler adds no dependencies.
- The accept loop returns from `Start()` cleanly when `Stop()` closes the
  listener; in-flight connections are closed so their goroutines exit.
- Only use this against systems you are authorized to test.
