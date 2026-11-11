# Web UI login with authentik

Configure authentik application policies to admit only the users or groups that
can administer Codex GitLab Review. Every admitted user can use all UI controls.

## Configure authentik

1. Create an application with an **OAuth2/OpenID Provider**.
2. Select a **Confidential** client and enable the authorization code flow.
3. Set a strict redirect URI: `https://review.example.com/auth/callback`.
4. Keep the default issuer mode, **Each provider has a different issuer**.
5. Select a signing key and include the `openid` scope mapping.
6. Add the application's user, group, or policy bindings to restrict access.
7. Copy the client ID, client secret, and issuer URL to the service configuration.

For an application with slug `codex-review`, the issuer URL is normally
`https://auth.example.com/application/o/codex-review/`. Keep the trailing slash.
The server must reach the provider's discovery, JWKS, and token endpoints.
See the [authentik provider documentation](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/)
and [application policy setup](https://docs.goauthentik.io/add-secure-apps/applications/manage_apps/).

## Configure the service

```yaml
server:
  bind_addr: "0.0.0.0:8080"
  status_ui_enabled: true
  oidc:
    issuer_url: "https://auth.example.com/application/o/codex-review/"
    client_id: "codex-review"
    redirect_url: "https://review.example.com/auth/callback"
```

Supply the client secret with `CODEX_REVIEW__SERVER__OIDC__CLIENT_SECRET`.
The public callback URL determines whether the browser cookie requires HTTPS.
The service can receive HTTP from a TLS-terminating proxy. It does not use
forwarded headers to choose the callback or cookie security.
HTTP callback URLs are accepted only for loopback development addresses.
The callback must be at `/auth/callback`, without a URL path prefix.

Omit `server.oidc` to keep proxy-managed authentication. `status_ui_enabled`
continues to control whether the UI and its login routes exist.

## Configure Helm

Create a Kubernetes Secret that contains the client secret. Set these values:

```yaml
config:
  server:
    statusUiEnabled: true
    oidc:
      enabled: true
      issuerUrl: "https://auth.example.com/application/o/codex-review/"
      clientId: "codex-review"
      redirectUrl: "https://review.example.com/auth/callback"
      clientSecret:
        existingSecret: "codex-review-oidc"
        secretKey: "client-secret"
```

Configure the ingress and TLS for the public hostname. The chart reads the
client secret from the named Secret. It keeps the secret out of its ConfigMap.

## Sessions and access

Unauthenticated UI requests redirect to login and return to their original page.
JSON endpoints and write requests return `401 Unauthorized` without a session.
`/healthz` stays public. Existing CSRF checks also apply after login.

Sessions expire when the ID token expires, with an eight-hour upper limit.
There is no automatic token refresh. The service stores only session IDs in
HttpOnly, SameSite=Lax browser cookies. It validates token signatures, issuer,
audience, expiration, nonce, and any access token hash through the OIDC library.
Login attempts expire after ten minutes and use state verification and PKCE.

The process-local session store uses a 10,000-entry LRU cache with automatic
expiry. At capacity, new sessions replace the least-recently-used entries.
Restarting the service or evicting an entry requires a new login.
The existing Helm deployment runs one replica. Multiple independent replicas
require session affinity or a shared session store before deployment.

The **Sign out** link ends the local session after confirmation. It does not end
the authentik session. Changes to authentik admission policies apply on the next
login. This service does not implement provider-initiated logout or immediate
session revocation when authentik policies change.
