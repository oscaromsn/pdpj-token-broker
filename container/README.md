# Browser fallback container

Drives a real Chromium through the PDPJ login when the HTTP transport reports
`ChallengeRequired` — a captcha or JS wall the form replay cannot answer.

**The HTTP interface — endpoints, request and reply shapes, status codes,
concurrency, and the trust boundary — is documented in the root
[`README.md`](../README.md#the-browser-fallback-service).** This file covers
only how the image is built and where to run it.

## Why the Dockerfile looks like this

- **Two stages.** A `node:22-slim` builder bundles `container/server.ts` into a
  single JS file; the runtime image carries that file and `playwright-core`,
  with no TypeScript toolchain and no `node_modules` tree. Smaller attack
  surface for a service that handles plaintext passwords.
- **The `createRequire` banner is load-bearing.** Several transitive deps
  (`ws`, via playwright-core's driver) are CommonJS and call `require` at
  import time. Without the banner, esbuild emits a stub that throws
  `Dynamic require of "events" is not supported` the moment the process
  starts — a failure invisible to both `tsc` and the build.
- **`playwright-core` stays external.** It resolves browser binaries by path at
  runtime; bundling it breaks that lookup.
- **`tini` as entrypoint.** Chromium leaves zombie processes behind. With no
  init to reap them they accumulate across logins until the container hits its
  PID limit and can no longer launch a browser at all.
- **Non-root (`pwuser`).** Chromium runs with `--no-sandbox`, because the
  container is the isolation boundary and the kernel namespaces its sandbox
  wants are unavailable inside one. Not running the whole service as root is
  the compensating control, not an optional nicety.
- **`--disable-dev-shm-usage`.** Containers get a 64 MB `/dev/shm` by default,
  which Chromium exhausts and then dies with no useful error. `--ipc=host`
  covers this where the runtime allows it; the flag covers where it does not.

## Deploy

The service speaks plain authenticated HTTP, so it runs anywhere the broker can
reach by URL. Point the broker at it with two env vars:

```
BROWSER_SERVICE_URL   = https://<host>         # where this service listens
BROWSER_SERVICE_TOKEN = <shared secret>        # must match this service's token
```

Generate the shared token once (`make token`, or `openssl rand -base64 32`) and
set it on **both** sides.

### docker compose (a VM, or locally)

```bash
# from the repo root
export BROWSER_SERVICE_TOKEN=$(openssl rand -base64 32)
docker compose -f container/docker-compose.yml up --build -d
curl -fsS http://127.0.0.1:8080/health
```

The compose file carries the settings a browser workload actually needs and an
ordinary web service does not: `shm_size: 1gb` (Chromium shares `/dev/shm`, and
the 64 MB default crashes it), `init: true` (reap zombie Chromium children), and
explicit memory/CPU limits. The port is published on **loopback only** — this
service is inside the vault's trust boundary and must not face the internet.
Front it with TLS and reach it privately.

### Fly.io (recommended for a standalone service)

Fly keeps one warm Chromium per machine and can stay on its private network, so
the browser is never public:

```bash
fly launch --no-deploy --dockerfile container/Dockerfile     # once
fly secrets set BROWSER_SERVICE_TOKEN=$(openssl rand -base64 32)
fly deploy --dockerfile container/Dockerfile
```

Then set `BROWSER_SERVICE_URL=http://<app>.flycast` (private) or
`https://<app>.fly.dev` (public + token). `min_machines_running = 1` in
`fly.toml` keeps a machine warm so queries don't pay a cold Chromium launch.

### What about Cloudflare Containers?

The broker's Worker and the rest of the stack are on Cloudflare, so this looks
tempting — but Cloudflare Containers are reached through a Durable Object
binding, **not** a URL. The `ContainerBrowserLogin` / `BrowserProcessQuery`
adapters call a plain HTTP URL, so running on Cloudflare Containers would mean
reworking those adapters to a DO binding. The `BrowserService` resource in
`src/infra/resources.ts` is stubbed for that path; it is not a drop-in with the
current adapters. For now, a standalone host (Fly, a VM, ECS, Kubernetes) is the
simpler and matching choice.

## Version pinning

The base image tag and the `playwright-core` version must match **exactly**
(both `1.62.1` today, in the builder, the runtime stage, and the root
`package.json`). The image stores browsers under a version-stamped path; a
mismatched client looks for a directory that is not there and fails at the
first login rather than at build time.
