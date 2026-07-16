---
title: TLS / ACME Setup
description: Automatic HTTPS certificates via Let's Encrypt for the HTTPX handler
weight: 20
---

The HTTPX handler can automatically provision and renew TLS certificates
via [Let's Encrypt](https://letsencrypt.org/) using
[certmagic](https://github.com/caddyserver/certmagic). Two challenge
methods are supported: **DNS-01** (recommended — works behind firewalls
and supports wildcards) and **HTTP-01 / TLS-ALPN-01** (requires ports 80
and 443 to be reachable from the internet).

## Prerequisites

- A domain (or subdomain) whose DNS you control.
- For DNS-01: API credentials for a supported DNS provider (Namecheap or
  Route53).
- For HTTP-01: ports 80 and 443 open and reachable from the public
  internet.

## Quick start (DNS-01 with Namecheap)

```yaml
handlers:
  - handler: HTTPX
    listener: :80
    tls_names: "*.oob.example.com,oob.example.com"
    acme_email: you@example.com
    acme_accept: "true"
    acme_url: https://acme-staging-v02.api.letsencrypt.org/directory
    dns_provider: namecheap
    dns_provider_api_user: your-namecheap-user
    dns_provider_api_key: your-namecheap-api-key
```

Start with the **staging** ACME URL to avoid rate limits while testing.
Once certificates provision correctly, switch to production (see below).

## Configuration reference

| Key | Required | Default | Notes |
|-----|----------|---------|-------|
| `tls_names` | yes | — | Comma-separated hostnames. Setting any value enables HTTPS. Wildcards (e.g. `*.example.com`) require DNS-01. |
| `acme_email` | no | — | Contact address for the ACME account. Let's Encrypt sends expiry warnings here. |
| `acme_accept` | yes | `false` | Must be the literal string `"true"` to accept the CA's terms of service. Other values (`"yes"`, `"1"`) are treated as false. |
| `acme_url` | no | LE production | ACME directory URL. Use `https://acme-staging-v02.api.letsencrypt.org/directory` for testing. |
| `dns_provider` | no | — | `namecheap` or `route53`. When set, DNS-01 is used exclusively (HTTP-01 and TLS-ALPN-01 are disabled). |
| `dns_provider_api_user` | no | — | Namecheap API username (namecheap only). |
| `dns_provider_api_key` | no | — | Namecheap API key (namecheap only). |

## Challenge methods

### DNS-01 (recommended)

When `dns_provider` is set, xodbox creates TXT records via the provider's
API to prove domain ownership. HTTP-01 and TLS-ALPN-01 are disabled. A
hardcoded 30-second propagation delay gives DNS time to converge.

DNS-01 is the only option that supports **wildcard certificates** and
works when ports 80/443 are behind a firewall or NAT.

### HTTP-01 / TLS-ALPN-01 (fallback)

When `dns_provider` is not set, certmagic uses its default challenge
methods. This requires:

- **Port 80** reachable from the internet (HTTP-01 challenge).
- **Port 443** reachable from the internet (TLS-ALPN-01 and serving).

Note: in HTTPS mode, xodbox always binds ports 80 and 443 directly
(via certmagic), regardless of the `listener` config value.

## DNS provider setup

### Namecheap

1. Enable API access in your Namecheap account (Profile → Tools → API
   Access).
2. Whitelist your xodbox server's IP.
3. Set `dns_provider_api_user` and `dns_provider_api_key` in the config.

```yaml
dns_provider: namecheap
dns_provider_api_user: your-username
dns_provider_api_key: your-api-key
```

### Route53

The Route53 provider uses the **standard AWS SDK credential chain** — no
xodbox-specific config keys are needed beyond `dns_provider: route53`.
Provide credentials via one of:

- **Environment variables:** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
  `AWS_REGION`
- **Shared credentials file:** `~/.aws/credentials` (with optional
  `AWS_PROFILE`)
- **IAM instance profile / role:** when running on EC2, ECS, or similar
  AWS infrastructure
- **Web identity token:** for EKS / Kubernetes workloads

The IAM policy must allow `route53:ListHostedZones`,
`route53:ChangeResourceRecordSets`, and `route53:GetChange` on the
relevant hosted zone.

```yaml
dns_provider: route53
```

## Staging to production workflow

1. **Start with staging.** Set `acme_url` to the Let's Encrypt staging
   directory. Staging has generous rate limits and issues untrusted
   certificates — browsers will warn, but you can verify the flow works.

2. **Verify.** Start xodbox and confirm certificates provision (check the
   logs for certmagic messages). Test with `curl -k` or a browser that
   accepts untrusted certs.

3. **Switch to production.** Remove or clear `acme_url` (the default is
   Let's Encrypt production) or set it explicitly:

   ```yaml
   acme_url: https://acme-v02.api.letsencrypt.org/directory
   ```

4. **Restart xodbox.** Production certificates will be provisioned and
   trusted by browsers.

## Example configurations

### Wildcard certificate with Namecheap

```yaml
handlers:
  - handler: HTTPX
    listener: :80
    tls_names: "*.oob.example.com,oob.example.com"
    acme_email: ops@example.com
    acme_accept: "true"
    dns_provider: namecheap
    dns_provider_api_user: ncuser
    dns_provider_api_key: nckey123
    admin_listener: 127.0.0.1:9091
```

### Single domain with Route53

```yaml
handlers:
  - handler: HTTPX
    listener: :80
    tls_names: oob.example.com
    acme_email: ops@example.com
    acme_accept: "true"
    dns_provider: route53
```

### HTTP-01 (no DNS provider)

```yaml
handlers:
  - handler: HTTPX
    listener: :80
    tls_names: oob.example.com
    acme_email: ops@example.com
    acme_accept: "true"
```

Requires ports 80 and 443 open to the internet. Does not support wildcard
certificates.

## Troubleshooting

**"acme_accept must be true":** The value must be the exact string
`"true"`. Quoting matters in YAML — `acme_accept: true` (boolean) works,
but `acme_accept: yes` does not.

**Rate limited by Let's Encrypt:** You hit the production rate limit.
Switch to the staging URL, fix your config, then retry production after
the rate limit window (usually 1 hour for failed validations, 1 week for
duplicate certificates).

**DNS-01 challenge fails:** Verify your API credentials, check that the
domain's authoritative nameservers are correct, and allow at least 30
seconds for DNS propagation.

**Port 80/443 already in use:** In HTTPS mode, certmagic binds these
ports directly. Stop any other service on those ports before starting
xodbox.

**Certificates not renewing:** certmagic handles renewal automatically
(well before expiry). If renewal fails, check the logs for ACME errors —
usually a DNS or network issue.
