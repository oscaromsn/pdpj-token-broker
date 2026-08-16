# PDPJ Token Broker

A multi-tenant service that turns a stored CPF + password + TOTP seed into a
short-lived PDPJ access token, on demand and unattended.

Callers hold a credential *id*, never a secret. The broker owns the login, the
second factor, the refresh cycle, and the failure policy.

## Why it works this way

The password grant is dead at CNJ's SSO — `portalexterno-frontend` and `jusbr`
both answer `Client not allowed for direct access grants`, and device flow is
disabled too. The only route to a token is the `authorization_code` dance a
browser performs. The national login page still serves a plain CPF + password
form alongside gov.br and certificate options, so that dance can be driven over
plain HTTP for accounts holding a real JUSBR password.

Everything else follows from making that cheap and safe to repeat.

## Architecture

Hexagonal. The domain and the broker are written against ports; adapters bind
them to Keycloak, D1, and KV. `src/worker.ts` is the only file that knows which
is which.

```
src/
  domain/    Cpf · TotpSeed · Model · Errors        pure, no I/O
  ports/     CredentialVault · CredentialStore · KeyRing · TokenCache
             SsoClient · BrowserLogin · TotpGenerator · AuditLog · TenantAuth
  broker/    TokenBroker                            the cascade
  crypto/    Envelope                               AES-256-GCM on WebCrypto
  api/       schema-first HttpApi contract
  server/    handlers + bearer-key middleware
  adapters/  sso/ vault/ store/ cache/ browser/
  infra/     Cloudflare resource declarations
  worker.ts  composition root
```

### The cascade

Every token request walks the same rungs, stopping at the first that works:

1. **Cache hit** — a KV token with more than 60s of life left.
2. **Single-flight** — concurrent callers join one in-flight mint, they do not
   each start their own.
3. **Refresh** — the `refresh_token` grant, which does *not* re-trigger 2FA.
   This is what carries steady-state traffic.
4. **HTTP login** — Keycloak form replay plus a generated TOTP code.
5. **Browser fallback** — only on `ChallengeRequired`; a container running
   Playwright.

A failed login trips a circuit breaker rather than retrying. That is the single
most important guard here: repeated attempts are what get a real lawyer's
account locked at the SSO.

### Security posture

- Credentials are sealed with AES-256-GCM under a per-tenant key derived from
  one master key via HKDF. No data key exists at rest anywhere.
- The master key is read from the deploy environment via `Config.redacted` and
  bound onto the Worker as `secret_text`; it is never committed and never read
  back out.
- `Redacted` types make emitting a secret a *type* error. There is exactly one
  deliberate unwrap, at the token endpoint, which is the one place that is
  supposed to emit one.
- API keys are stored as SHA-256 hashes; a database dump yields nothing usable.
- Listing credentials never unseals anything, so it cannot leak even with a
  compromised key service.
- Tenant scoping is in the schema — `PRIMARY KEY (tenant_id, id)` — not in every
  query remembering to filter.

Storing the TOTP seed beside the password is what makes the pipeline
unattended, and also what raises the stakes: a vault compromise yields
*factor-complete* access to a lawyer's court identity, sealed cases included.
Treat the master key accordingly.

## Development

```bash
bun install
bun run test        # 100 tests, no network, no cloud account
bun run typecheck
```

### Live SSO test

Opt-in, and gated on both a flag and credentials:

```bash
PJE_ENABLE_LIVE_TESTS=1 \
PDPJ_CPF=... PDPJ_PASSWORD=... PDPJ_TOTP_SEED=... \
bun run test:live
```

Only the success path exists. There is deliberately no live "wrong password"
test — deliberately failing logins against a real account is exactly what the
circuit breaker exists to prevent.

### End-to-end check against the real PDPJ

`scripts/e2e.ts` walks the whole chain and reports at each step. It has two
modes, because the two things that can be wrong fail very differently and
conflating them wastes an afternoon:

```bash
# 1. Is this credential usable at all? No deploy, no database, no API key.
PDPJ_CPF=... PDPJ_PASSWORD=... PDPJ_TOTP_SEED=... \
  bun run e2e --direct

# 2. Does the deployed service work? Only worth running once (1) passes.
PDPJ_CPF=... PDPJ_PASSWORD=... PDPJ_TOTP_SEED=... \
  bun run e2e --broker https://broker.example.workers.dev --key pdpj_...
```

Both end by querying PDPJ for a real process (`--processo`, defaulting to the
case this project was built to reach), because minting a well-formed JWT proves
nothing about whether PDPJ will honour it.

It performs a **real login against a real account**: one attempt, never
retried. Malformed input is rejected before anything touches the network, so a
typo can never cost lockout budget. Each failure names the likely cause —
a refused password is called out as terminal and *not* to be retried, a 429 as
an open breaker, a 403 as valid-credential-without-standing.

That last distinction is the one to expect on a sealed process. A token proves
who you are, not that you have standing in a particular case: unless the
account is a party or counsel of record, PDPJ will refuse it no matter how
healthy the broker is.

## Deploying

Alchemy is Infrastructure-as-Effects: `src/worker.ts` *is* the deployment
description. Binding a resource there is what provisions it, wires the
environment variable, and hands the Worker a typed client.

### One-time auth

```bash
bunx alchemy login          # OAuth in the browser, or paste an API token
```

Credentials land in `~/.alchemy/profiles.json` under the `default` profile.
Use `--profile prod` to keep a separate set. No environment variables needed.

### Preview, then apply

```bash
bunx alchemy plan           # shows the plan, changes nothing
bunx alchemy deploy         # plan → approve → apply
bunx alchemy deploy --stage prod
bunx alchemy destroy --stage pr-42
```

`plan` currently reports **3 to create** — the Worker, the D1 database, and the
KV namespace.

Only `VAULT_MASTER_KEY` is required to deploy:

```bash
export VAULT_MASTER_KEY=...          # >= 32 chars
```

`BROWSER_SERVICE_URL` and `BROWSER_SERVICE_TOKEN` are optional, so the broker
deploys standalone before the browser container exists. Until they are set, a
`ChallengeRequired` fails as `SsoUnavailable` — correct, since there is
genuinely no browser to escalate to.

Deploy prints `accountId` and `databaseId`, which is what the key tool needs.

These are read by `Config.redacted` / `Config.string` during the Worker's init
phase, which is what makes Alchemy bind them as `secret_text` automatically.

### Provisioning tenant API keys

Every endpoint is behind a bearer key, and **nothing in the deployed service
writes the `api_keys` table** — deliberately. An endpoint that mints
credentials for arbitrary tenants would be the most dangerous surface here, and
it would need its own bootstrap credential to protect, which is the same
problem one rung up. Keys are provisioned from outside the network instead:

```bash
# against the deployed D1 database
CLOUDFLARE_API_TOKEN=... bun run keys mint \
  --tenant acme --label "CI pipeline" \
  --account <cf-account-id> --database <d1-database-id>

bun run keys list   [--tenant acme] ...
bun run keys revoke --hash <key-hash> ...
```

The key is printed to stdout exactly once and never stored — only its SHA-256
hash reaches the database, so a dump yields nothing usable. Everything else
goes to stderr, so it can be piped somewhere safe:

```bash
bun run keys mint --tenant acme --label CI ... > key.txt
```

Revocation is by hash, not by plaintext: an operator revoking a key usually
does not have it — that is often *why*. Hashes are listed by `keys list`, and
revoked rows are kept rather than deleted so the audit trail still points at
something real.

For local development, point it at a SQLite file instead:

```bash
bun run keys mint --tenant acme --label dev --sqlite ./dev.db
```

`--sqlite` requires Node (`bun run keys` already routes through it); Bun has no
`node:sqlite`. Remote mode runs under either.

### Stages

Every deploy targets one stage, and stages never share state or physical
names. The default is `dev_$USER`, so each developer gets a sandbox for free.
`--stage prod` for production, `--stage pr-42` for a preview.

### Non-interactive environments

CI — and any agent session, including Claude Code — is detected and forced into
plain output, which **never prompts and never applies**. Pass `--yes` to
approve:

```bash
bunx alchemy deploy --stage prod --yes
```

### Before deploying from CI

The stack currently uses `Alchemy.localState()`, which keeps state in
`.alchemy/` on the deploying machine. That is right for solo development and
wrong for a team: two people deploying the same stage would each compute diffs
against their own copy. Switch `alchemy.run.ts` to `Cloudflare.state()` so all
deploys share one store.

## The browser fallback service

The last rung of the cascade runs in its own container, because Playwright
cannot run inside a Worker. The Worker reaches it over plain authenticated
HTTP — `src/adapters/browser/ContainerBrowserLogin.ts` on one side,
`container/server.ts` on the other — so the host is a URL and a token rather
than an architectural commitment.

It is invoked **only** on `ChallengeRequired`: a captcha or JS wall the HTTP
form replay cannot answer. A rejected password never gets here, because a
browser would be rejected identically and the extra attempt would spend the
account's lockout budget for nothing.

### Trust boundary

The request carries a **plaintext CPF, password and TOTP seed**. It has to —
something must type them into a login form. That puts this service *inside* the
vault's trust boundary, not beside it:

- never expose it to the internet;
- reach it over TLS on a private network;
- `BROWSER_SERVICE_TOKEN` is checked on every request in constant time.

Anything that can reach the port can otherwise ask it to log in as any lawyer
whose credentials it is handed.

### `POST /login`

```http
POST /login
Authorization: Bearer <BROWSER_SERVICE_TOKEN>
Content-Type: application/json

{
  "cpf": "52998224725",
  "password": "…",
  "totpSeed": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"   // optional
}
```

`totpSeed` is omitted when the account has no second factor enrolled. If the
SSO then asks for one anyway, the service reports `InvalidTotp` rather than
hanging.

A **login that fails is still a 200.** The transport succeeded; the credential
did not. The outcome is carried in the body as a tagged union, because the
difference between "wrong password" and "wrong code" drives different operator
action and must survive the hop intact:

```jsonc
{ "_tag": "Success", "accessToken": "eyJ…", "expiresAt": 1786893763843 }
{ "_tag": "InvalidPassword", "detail": "Usuário ou senha inválido" }
{ "_tag": "InvalidTotp",     "detail": "Código de autenticação inválido" }
{ "_tag": "Failed",          "detail": "browser crashed" }
```

`expiresAt` is absolute epoch millis. A token scraped from a request header
carries no `expires_in`, so the service assumes five minutes — short enough
that the cache can never serve a dead one.

HTTP status is reserved for the transport itself:

| Status | Meaning | Broker sees |
| --- | --- | --- |
| `200` | Reached the SSO; read the `_tag` for the outcome | mapped per tag |
| `400` | Body was unreadable or failed schema validation | `SsoUnavailable` |
| `401` | Missing or wrong bearer token | `SsoUnavailable` |
| `500` | Unexpected defect; the process survives | `SsoUnavailable` |

Everything that is not a `200` collapses to `SsoUnavailable` on the Worker
side — transient, and subject to the circuit breaker. Only `InvalidPassword`
and `InvalidTotp`, which arrive inside a `200`, are treated as terminal.

The client does **not** retry. Retrying here would multiply attempts against
the SSO behind the breaker's back; the caller's 90-second timeout and the
breaker own that decision.

### `GET /health`

Unauthenticated liveness, so an orchestrator can reach it. `200 ok` while the
browser is connected, `503 browser down` otherwise — a launched-but-dead
Chromium is the failure this exists to catch, and it is invisible to a plain
port check.

### Concurrency

At most **three** logins run at once. Each drives a live page, and a handful in
parallel will exhaust a small container rather than merely slow it; queuing is
the better failure mode. One Chromium is launched per process and reused, with
a fresh browser context per attempt — the same isolation requirement as the
per-attempt cookie jar on the HTTP path, and for the same reason.

### Running it

```bash
docker build -f container/Dockerfile -t pdpj-browser .

docker run --rm --init --ipc=host \
  --memory=2g --cpus=2 \
  -e BROWSER_SERVICE_TOKEN=... \
  -p 8080:8080 \
  pdpj-browser
```

The base image tag and the `playwright-core` version must match exactly (both
`1.62.1`): the image stores browsers under a version-stamped path, and a
mismatched client fails at the first login rather than at build time.

`container/README.md` covers the operational detail — why `tini`, why
`--ipc=host`, why non-root, and where to host it.

## What is verified, and what is not

The suite runs with no network and no cloud account, and covers the domain, the
cascade, the crypto, the vault, the SSO flow, the API surface, and the SQL —
the last against real SQLite, which is the same engine D1 runs.

Three things are **not** covered and need a live run before you trust them:

1. **The browser interaction in `adapters/browser/PlaywrightLogin.ts`.** The
   container around it *is* exercised: the bundle builds, loads, resolves its
   config and reaches `chromium.launch()` — which is how the CommonJS-`require`
   bug in the bundle was caught. What is unproven is the page driving itself:
   the selectors, the OTP step, and scraping the bearer token off the portal's
   own XHR. That needs a real Chromium and a real account, and its failure
   paths would mean deliberately failing logins. Selectors match the recorded
   login page and the logic is ported from PJePA's live-tested client.
2. **The `SqlExecutor` → D1 translation in `worker.ts`** — a dozen lines mapping
   onto Cloudflare's `PreparedStatement`. Everything above that seam is tested.
3. **The deployed Worker's runtime wiring.** `alchemy plan` succeeds and the
   whole program typechecks, so the resource graph and the bindings are sound.
   What a plan cannot prove is the runtime half: that `RuntimeContext` grounds
   the D1 and KV clients correctly inside `fetch`, and that `Effect.cached`
   builds the adapter graph once per cold start rather than per request. Both
   need a real deploy and one real request.

`test/sso/fixtures/login-page.html` is a real captured response. The OTP, error
and captcha fixtures are constructed from Keycloak's stock templates and are
labelled as such in that directory's README — they are not passed off as
recordings.
