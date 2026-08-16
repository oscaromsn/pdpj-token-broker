# syntax=docker/dockerfile:1

# ─────────────────────────────────────────────────────────────────────────────
# Browser fallback service
#
# Drives a real Chromium through the PDPJ login when the HTTP transport hits a
# captcha. Reached only on `ChallengeRequired`, so this is a cold, occasional
# path — optimized for not falling over rather than for throughput.
#
# Build context is the repo root, because the server imports the adapter and
# the wire protocol from `src/`:
#
#   docker build -f container/Dockerfile -t pdpj-browser .
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: bundle ──────────────────────────────────────────────────────────
# Bundling means the runtime image carries one JS file instead of a TypeScript
# toolchain and a node_modules tree, which keeps the attack surface of a
# service that handles plaintext passwords as small as it can be.
FROM node:22-bookworm-slim AS builder

WORKDIR /build

COPY package.json bun.lock* package-lock.json* ./
RUN npm install --no-audit --no-fund

COPY tsconfig.json ./
COPY src ./src
COPY container ./container

# `playwright-core` stays external: it resolves browser binaries by path at
# runtime, and bundling it breaks that lookup.
# The `createRequire` banner is load-bearing: several transitive dependencies
# (`ws`, reached through playwright-core's driver) are CommonJS and call
# `require` at import time. Without it esbuild emits a stub that throws
# "Dynamic require of \"events\" is not supported" the moment the process
# starts — a failure that only shows up at runtime, never at build time.
RUN npx --yes esbuild container/server.ts \
      --bundle \
      --platform=node \
      --target=node22 \
      --format=esm \
      --external:playwright-core \
      --banner:js="import{createRequire as __cr}from'node:module';const require=__cr(import.meta.url);" \
      --outfile=dist/server.mjs

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
# The tag MUST match the installed `playwright-core` version exactly. The image
# ships browser binaries under a version-stamped path, and a mismatched client
# looks for a directory that is not there — failing at first login with a
# "browser not found" error rather than at build time.
FROM mcr.microsoft.com/playwright:v1.62.1-noble AS runtime

# `tini` reaps the zombie processes Chromium leaves behind. Without an init,
# defunct children accumulate across logins until the container hits its PID
# limit and stops being able to launch a browser at all.
RUN apt-get update \
  && apt-get install -y --no-install-recommends tini \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Only the browser driver, and pinned to the image's version.
RUN npm install --no-audit --no-fund --omit=dev playwright-core@1.62.1

COPY --from=builder /build/dist/server.mjs ./server.mjs

ENV NODE_ENV=production \
    PORT=8080 \
    # Use the browsers baked into the image rather than downloading any.
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

# `pwuser` ships with the Playwright image. Chromium runs with `--no-sandbox`
# because the container is the isolation boundary and the kernel namespaces it
# would otherwise use are unavailable inside one — so *not* running the whole
# service as root is the compensating control, not an optional nicety.
USER pwuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "server.mjs"]
