---
title: OIDC / SSO
description: Configure single sign-on for the admin console via OpenID Connect
weight: 10
---

The admin console supports single sign-on via any OpenID Connect provider
(Google, Okta, Keycloak, Azure AD, Authentik, Dex, etc.). SSO runs
**alongside** built-in username/password login — a local admin can always
sign in even when the IdP is down or misconfigured.

## Prerequisites

- A working xodbox instance with the admin console enabled
  (`admin_listener` or `ui_path` configured).
- An OIDC provider with a client application registered for xodbox.

## Register xodbox with your identity provider

Create an application / client in your IdP with these settings:

| Setting | Value |
|---------|-------|
| Application type | Web |
| Grant type | Authorization Code |
| PKCE | S256 (always used; required for public clients) |
| Redirect URI | `<admin_base>/api/auth/oidc/callback` (e.g. `https://oob.example.com/admin/api/auth/oidc/callback`) |
| Scopes | `openid profile email` (minimum) |

Note the **Issuer URL** and **Client ID** — those are the two required
values. A **Client Secret** is optional when the provider supports public
clients with PKCE.

## Minimal configuration

Add the OIDC keys to your HTTPX handler entry in `xodbox.yaml`:

```yaml
handlers:
  - handler: HTTPX
    listener: :80
    admin_listener: 127.0.0.1:9091
    oidc_issuer: https://sso.example.com/realms/corp
    oidc_client_id: xodbox
```

This is enough to enable the SSO button on the login page. Discovery
(`<issuer>/.well-known/openid-configuration`) is fetched lazily on the
first login attempt, so xodbox starts even if the IdP is temporarily
unreachable.

## Full configuration reference

| Key | Default | Description |
|-----|---------|-------------|
| `oidc_issuer` | — | Provider issuer URL. Required to enable SSO. |
| `oidc_client_id` | — | OAuth2/OIDC client ID. Required to enable SSO. |
| `oidc_client_secret` | (empty) | Client secret. Omit for public clients — the flow always uses PKCE. |
| `oidc_redirect_url` | derived | Callback URL. When empty it is derived from the request's scheme, host, and admin mount path (honoring `X-Forwarded-Proto`). Set it explicitly when behind a reverse proxy. |
| `oidc_scopes` | `openid,profile,email` | Comma or space-separated scopes. `openid` is always included. |
| `oidc_default_role` | `user` | Role assigned to provisioned users: `user` or `admin`. |
| `oidc_groups_claim` | `groups` | ID-token claim inspected for group membership. May be a JSON array, space-separated string, or comma-separated string. |
| `oidc_admin_group` | (empty) | When set, users whose groups claim contains this value get the `admin` role; everyone else gets `oidc_default_role`. |
| `oidc_button_label` | `Sign in with SSO` | Text shown on the login page's SSO button. |

## How the login flow works

1. The user clicks **Sign in with SSO** on the login page.
2. The browser hits `GET /api/auth/oidc/login`, which generates a `state`,
   `nonce`, and PKCE code verifier, stashes them in short-lived cookies,
   and redirects to the identity provider's authorization endpoint.
3. After the user authenticates, the provider redirects back to
   `GET /api/auth/oidc/callback`.
4. xodbox validates `state`, exchanges the authorization code (with the
   PKCE verifier), and verifies the ID token's signature and `nonce`.
5. A local account is provisioned (or updated) from the token's claims and
   a standard session cookie is issued — identical to the one the password
   flow creates. All downstream middleware (CSRF, roles, API keys) works
   the same regardless of login method.

## User provisioning

Accounts are created **just-in-time** on first OIDC login. Key behaviours:

- The account is keyed by `iss#sub` (issuer + subject), never by email, so
  a colliding email address cannot take over an existing local account.
- OIDC-provisioned accounts have no password and can never be used for
  password login.
- The display name is derived from `preferred_username`, `email`, or `sub`
  (first non-empty wins). If the chosen username is already taken, a
  numeric suffix is appended.
- On every login the user's role is re-synced from the current token
  claims, so IdP group changes take effect immediately.

## Role mapping

Without `oidc_admin_group`, every OIDC user gets the `oidc_default_role`
(default `user`). Set `oidc_admin_group` to a group value present in the
`oidc_groups_claim` to promote matching users to `admin`:

```yaml
oidc_groups_claim: groups        # claim name in the ID token
oidc_admin_group: xodbox-admins  # value that grants admin
oidc_default_role: user          # everyone else
```

The groups claim can be a JSON array (`["a","b"]`), a space-separated
string (`"a b"`), or a comma-separated string (`"a,b"`).

## Reverse proxy considerations

When xodbox sits behind a reverse proxy:

- Set `oidc_redirect_url` explicitly to the externally-reachable callback
  URL. The auto-derived URL uses the request's `Host` and
  `X-Forwarded-Proto` headers, which may not be correct in all proxy
  configurations.
- Ensure the proxy forwards `X-Forwarded-Proto` so xodbox can distinguish
  HTTP from HTTPS when building the redirect.

## Provider-specific examples

### Keycloak

```yaml
handlers:
  - handler: HTTPX
    listener: :80
    admin_listener: 127.0.0.1:9091
    public_url: https://oob.example.com
    oidc_issuer: https://sso.example.com/realms/corp
    oidc_client_id: xodbox
    oidc_client_secret: "change-me"
    oidc_redirect_url: https://oob.example.com/admin/api/auth/oidc/callback
    oidc_admin_group: xodbox-admins
```

In Keycloak, create a client with:
- Client type: OpenID Connect
- Client authentication: On (confidential) or Off (public + PKCE)
- Valid redirect URIs: `https://oob.example.com/admin/api/auth/oidc/callback`
- Add a **groups** mapper (Client scopes → dedicated scope → Add mapper →
  Group Membership) so the `groups` claim appears in the ID token.

### Google Workspace

```yaml
handlers:
  - handler: HTTPX
    listener: :80
    admin_listener: 127.0.0.1:9091
    oidc_issuer: https://accounts.google.com
    oidc_client_id: "123456789.apps.googleusercontent.com"
    oidc_client_secret: "GOCSPX-..."
    oidc_redirect_url: https://oob.example.com/admin/api/auth/oidc/callback
    oidc_default_role: user
```

Google does not expose a `groups` claim in the ID token, so group-based
admin mapping is not available. Grant the `admin` role from the Users page
after the user's first login, or set `oidc_default_role: admin` if every
Google user should be an admin.

### Okta

```yaml
handlers:
  - handler: HTTPX
    listener: :80
    admin_listener: 127.0.0.1:9091
    oidc_issuer: https://dev-123456.okta.com
    oidc_client_id: 0oa1bcdef
    oidc_client_secret: "..."
    oidc_redirect_url: https://oob.example.com/admin/api/auth/oidc/callback
    oidc_groups_claim: groups
    oidc_admin_group: xodbox-admins
```

In Okta, add a **Groups claim** to the ID token (Security → API →
Authorization Server → Claims → Add Claim with Include in: ID Token,
Value type: Groups, Filter: Matches regex `.*`).

## Troubleshooting

**SSO button does not appear:** both `oidc_issuer` and `oidc_client_id`
must be set. Check the server logs at start-up for an OIDC summary line
confirming SSO is enabled.

**"sso_error" on callback:** the login page shows the error from the query
parameter. Common causes: mismatched redirect URI, expired state cookie
(the user took too long), or the IdP returned an error. Check server logs
for the detailed error.

**User gets `user` role instead of `admin`:** verify that the ID token
actually contains the groups claim. Use your IdP's token preview or
decode the JWT to confirm. The claim name must match `oidc_groups_claim`
and the value must match `oidc_admin_group` exactly.

**IdP unreachable at start-up:** this is fine — discovery is lazy. The
first login attempt will fail with a clear error if the IdP is still
unreachable at that point.
