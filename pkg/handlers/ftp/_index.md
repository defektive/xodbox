---
title: FTP
description: FTP Handler
weight: 10
---

{{% alert title="In development feature" %}}
This feature is in development. Please help make it awesome by providing feedback on your experience using it.
{{% /alert %}}

## Purpose

An FTP listener that presents a fake directory tree to clients. Useful
for confirming out-of-band FTP fetches, picking up credential probes,
and observing what scanners look for. List/read/auth interactions are
emitted as `InteractionEvent`s; no real files are served.

## Behaviour

- Backed by [`fclairamb/ftpserverlib`](https://github.com/fclairamb/ftpserverlib).
- Filesystem is an in-memory afero `MemMapFs` seeded with the directory
  paths listed in `fake_dir_tree`. Operators can probe the tree but
  cannot write durable state.
- Plaintext authentication is allowed; reads/writes/lists emit
  fine-grained action events (`AuthSuccess`, `AuthFail`, `ListFiles`,
  `FileOpen`, `FileRead`, `FileWrite`, `FileReadDir`, `FileDelete`).
- The bundled `SimpleServerDriver.AuthUser` rejects every login
  unless `Credentials` has been populated programmatically. The
  current YAML schema does not expose `Credentials`; the default
  behaviour is therefore "log the attempt and refuse".

## Configuration

| Key            | Required | Default                         | Notes                                                                       |
|----------------|----------|---------------------------------|-----------------------------------------------------------------------------|
| `handler`      | yes      | —                               | Must be `FTP`.                                                              |
| `listener`     | yes      | —                               | Bind address, e.g. `:21` or `:2121` for unprivileged ports.                 |
| `server_name`  | no       | `FTP Server`                    | Banner returned to clients in the 220 greeting.                             |
| `fake_dir_tree`| no       | `test/old/fake,test/new/fake`   | Comma-separated paths created on the in-memory fs at startup.               |

## Events

| Action        | Trigger                                          |
|---------------|--------------------------------------------------|
| `AuthSuccess` | A USER/PASS pair matched a configured credential.|
| `AuthFail`    | Authentication was rejected.                     |
| `Logout`      | Client disconnected after auth.                  |
| `ListFiles`   | Client issued LIST/NLST.                         |
| `FileOpen`    | Client opened a file (RETR/STOR).                |
| `FileRead`    | Bytes read from a file.                          |
| `FileWrite`   | Bytes written to a file.                         |
| `FileReadDir` | Directory enumeration.                           |
| `FileDelete`  | DELE command.                                    |

## Operational notes

- Plaintext credentials submitted to this handler should be considered
  compromised; do not run it where users might accidentally type real
  passwords into it.
- `Stop()` calls the underlying `FtpServer.Stop()` (no context
  deadline; ftpserverlib does not accept one).
