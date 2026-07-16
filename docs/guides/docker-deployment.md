---
title: Docker Deployment
description: Run xodbox in Docker with persistent storage and multi-handler configurations
weight: 60
---

Pre-built Docker images are published to the GitHub Container Registry
(GHCR) and signed with cosign (keyless OIDC via GitHub Actions). The
images are Alpine-based, run as a non-root `xodbox` user, and contain a
single statically-linked binary.

## Quick start

```sh
# Generate a starter config
docker run --rm ghcr.io/defektive/xodbox:latest config -e > xodbox.yaml

# Edit xodbox.yaml to taste, then run
docker run -d \
  --name xodbox \
  -v "$PWD:/workspace" \
  --user "$(id -u):$(id -g)" \
  -p 80:80 \
  ghcr.io/defektive/xodbox:latest serve
```

## Image details

| Property | Value |
|----------|-------|
| Image | `ghcr.io/defektive/xodbox` |
| Tags | `:latest`, `:v1.2.3` (per release) |
| Architecture | `linux/amd64` |
| Base | `alpine:3.21` |
| Entrypoint | `/bin/xodbox` |
| Working directory | `/workspace` |
| Runs as | `xodbox` (non-root) |

## Volumes and persistence

The container's working directory is `/workspace`. Mount a host directory
there to persist:

| File | Purpose |
|------|---------|
| `xodbox.yaml` | Configuration file |
| `xodbox.db` | SQLite database (interactions, payloads, users) |
| `payloads/` | Custom payload files (if `payload_dir` is set) |
| `static/` | Static assets (if `static_dir` is set) |

Always pass `--user "$(id -u):$(id -g)"` so files created in the volume
are owned by your host user.

## Health check

The HTTPX handler exposes a health endpoint:

```
GET /api/health → {"status": "ok"}
```

When using `ui_path`, the endpoint is at `<ui_path>/api/health` (e.g.
`/admin/api/health`).

```yaml
# docker-compose healthcheck
healthcheck:
  test: ["CMD", "wget", "-q", "--spider", "http://localhost/api/health"]
  interval: 30s
  timeout: 5s
  retries: 3
```

## Docker Compose examples

### HTTP only

```yaml
services:
  xodbox:
    image: ghcr.io/defektive/xodbox:latest
    command: serve
    user: "1000:1000"
    ports:
      - "80:80"
    volumes:
      - ./data:/workspace
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost/api/health"]
      interval: 30s
      timeout: 5s
      retries: 3
```

### Multi-handler (HTTP + DNS + SMB)

```yaml
services:
  xodbox:
    image: ghcr.io/defektive/xodbox:latest
    command: serve
    user: "1000:1000"
    ports:
      - "80:80"
      - "53:53/udp"
      - "445:445"
      - "9091:9091"       # isolated admin console
    volumes:
      - ./data:/workspace
    restart: unless-stopped
    cap_add:
      - NET_BIND_SERVICE  # required for ports < 1024
```

With `xodbox.yaml` in `./data/`:

```yaml
handlers:
  - handler: HTTPX
    listener: :80
    admin_listener: 0.0.0.0:9091
    ui_allow_cidrs: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

  - handler: DNS
    listener: :53
    default_ip: 203.0.113.10

  - handler: SMB
    listener: :445
    target_name: CORP-FS01

notifiers:
  - notifier: app_log
```

### With TLS (ACME DNS-01)

```yaml
services:
  xodbox:
    image: ghcr.io/defektive/xodbox:latest
    command: serve
    user: "1000:1000"
    ports:
      - "80:80"
      - "443:443"
      - "53:53/udp"
    volumes:
      - ./data:/workspace
    environment:
      # For Route53 DNS-01 challenge
      - AWS_ACCESS_KEY_ID=AKIA...
      - AWS_SECRET_ACCESS_KEY=...
      - AWS_REGION=us-east-1
    cap_add:
      - NET_BIND_SERVICE
    restart: unless-stopped
```

## Behind a reverse proxy

When running behind nginx, Caddy, or another reverse proxy:

1. Forward `X-Forwarded-Proto`, `X-Forwarded-For`, and `Host` headers.
2. If using the admin console, set `public_url` to the external URL so
   sink links point to the right host.
3. If using OIDC, set `oidc_redirect_url` explicitly.

Example nginx upstream:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

## Bootstrapping users

Create the first admin user before or after starting the container:

```sh
# Before starting (if the DB doesn't exist yet)
docker run --rm -v "$PWD/data:/workspace" --user "$(id -u):$(id -g)" \
  ghcr.io/defektive/xodbox:latest user add alice --admin

# While running
docker exec xodbox /bin/xodbox user add alice --admin
```

## Verifying image signatures

```sh
cosign verify \
  --certificate-identity-regexp="https://github.com/defektive/xodbox" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/defektive/xodbox:latest
```

## Troubleshooting

**Permission denied on `/workspace`:** Pass `--user "$(id -u):$(id -g)"`
to match the host volume's ownership, or `chown` the data directory.

**Port 53 bind fails:** Add `cap_add: [NET_BIND_SERVICE]` in Compose or
`--cap-add NET_BIND_SERVICE` in `docker run`. Alternatively, bind to a
high port (e.g. `:5353`) and NAT from 53 externally.

**"address already in use" on port 53:** `systemd-resolved` or `dnsmasq`
may hold port 53. On the host, disable or reconfigure them.

**Database locked errors:** Only one xodbox instance should access the
SQLite database at a time. Do not mount the same volume into multiple
containers.
