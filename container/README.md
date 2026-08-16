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

## Build and run

```bash
docker build -f container/Dockerfile -t pdpj-browser .

docker run --rm --init --ipc=host \
  --memory=2g --cpus=2 \
  -e BROWSER_SERVICE_TOKEN=... \
  -p 8080:8080 \
  pdpj-browser
```

The build context is the repo root, because `container/server.ts` imports the
wire protocol and the Playwright adapter from `src/`.

## Version pinning

The base image tag and the `playwright-core` version must match **exactly**
(both `1.62.1` today, in the builder, the runtime stage, and the root
`package.json`). The image stores browsers under a version-stamped path; a
mismatched client looks for a directory that is not there and fails at the
first login rather than at build time.

## Where to host it

Cloudflare Containers suit this shape of workload — an occasional
"run a browser, return a result" call — but check the constraints against your
traffic first: browser cold-start latency, instance lifetime, and the memory
ceiling. (Chromium sandboxing is moot here; we disable it.)

For heavier or steadier use — a warm browser pool, long sessions, PDF or video
work — a conventional host (Kubernetes, ECS, Fly, a VM) gives more control over
CPU, memory, shared memory and autoscaling.

Nothing in the Worker cares. `ContainerBrowserLogin` speaks plain authenticated
HTTP, so the host is a `BROWSER_SERVICE_URL` and a token. The Alchemy
`Container` resource for the Cloudflare route is stubbed out in
`src/infra/resources.ts`, ready to uncomment once the image has been built.
