# Security Policy

## What xodbox Is (and Isn't)

xodbox is a **network interaction listening post** used to detect out-of-band
interactions during application security testing, CTF challenges, and research.
It deliberately presents itself as a permissive, easy-to-trigger target so
that pentesters can confirm whether an application reaches an attacker-
controlled host.

**xodbox is not a production-grade service.** Several design choices that are
appropriate for a test rig would be unsafe to operate as real infrastructure:

- The **SMTP handler** generates self-signed TLS certificates with a single
  long-lived key pair (`pkg/handlers/smtp/certs.go`). These certificates are
  intended to be cryptographically untrusted — clients accepting them are
  the bug the operator is hunting for. Do not place this handler in front of
  real mail traffic.
- The SMTP server runs with `AllowInsecureAuth = true`. Credentials submitted
  to it should be assumed compromised.
- The **FTP handler**'s `SimpleServerDriver` retains plaintext passwords in
  the configured `Credentials` slice. Use disposable values only.
- The **HTTP handler** mounts payload directories whose templates are
  evaluated with `text/template` and `html/template`. Anyone with write
  access to the payload directory can run code in the server process.
  Restrict the payload directory's permissions to the operator's account.

## Operating Guidance

- **Run as an unprivileged user.** The release container drops to a non-root
  user before invoking the binary.
- **Source secrets from environment variables** or a config file with
  restrictive permissions. `dns_provider_api_key`, `dns_provider_api_user`,
  and `api_token` end up in the xodbox config; that file should be `0600`
  and owned by the running user.
- **Bind low-numbered ports via Docker/systemd**, not via running xodbox as
  root. The Linux capability `CAP_NET_BIND_SERVICE` is sufficient for ports
  below 1024.
- **Bot suppression is heuristic.** `model.IsBot` flags a remote address as
  a bot after 30 interactions in a one-minute window. Determined automation
  can evade this; do not rely on bot suppression as a security boundary.
- **Inbound TLS is opt-in.** The HTTPS path uses certmagic + ACME; for any
  internet-exposed deployment, configure `tls_names`, accept the ACME ToS,
  and provide a real DNS provider key.

## Reporting a Vulnerability

If you believe you have found a security issue in xodbox itself (rather than
in code under test by xodbox), please open a GitHub Security Advisory at
<https://github.com/defektive/xodbox/security/advisories/new>. Avoid filing
public issues for vulnerabilities until a fix has shipped.

Please include:

- Affected version (`xodbox --version`)
- Configuration that reproduces the issue (handlers + notifiers enabled,
  relevant flags)
- Proof-of-concept request or sequence
- Expected vs observed behaviour

## Supported Versions

Only the latest tagged release receives fixes. Pin to a release tag rather
than tracking `main` if you need a stable artifact.
