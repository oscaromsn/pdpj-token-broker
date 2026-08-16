import * as Cloudflare from "alchemy/Cloudflare"

/**
 * The stack's stateful resources.
 *
 * Declared apart from the Worker so both `alchemy.run.ts` and the Worker can
 * reference the same identifiers: binding a resource is how the Worker gets a
 * typed client for it, and both halves must name the same thing.
 */

/**
 * Credentials, API keys and the audit trail.
 *
 * Migrations under `./migrations` are applied in numeric order on every
 * deploy; already-applied ones are skipped.
 */
export const Database = Cloudflare.D1.Database("Database", {
  migrationsDir: "./migrations"
})

/**
 * Short-lived access tokens.
 *
 * KV rather than D1 deliberately: this is a cache with per-entry TTLs and a
 * high read rate, and losing all of it costs one round of re-minting rather
 * than any data.
 */
export const TokenCacheNamespace = Cloudflare.KV.Namespace("TokenCache", {
  title: "pdpj-token-broker-tokens"
})

/**
 * The vault's master key is *not* declared here.
 *
 * It is read in the Worker with `Config.redacted("VAULT_MASTER_KEY")`, which
 * Alchemy binds onto the Worker as `secret_text` at deploy time. That is one
 * fewer resource, one fewer dependency edge, and the value still comes from
 * the deploying environment and is never committed.
 */

/**
 * The browser fallback, built from `container/Dockerfile`.
 *
 * Declared with `context` + `dockerfile` rather than Alchemy's `main` bundling
 * because the image must carry Chromium and its system libraries — there is no
 * Effect program to bundle that would produce a working browser.
 *
 * The build context is the repo root: `container/server.ts` imports the wire
 * protocol and the Playwright adapter from `src/`, so both must be visible to
 * the build.
 *
 * Commented out until the image has been built and pushed once. The Worker
 * reaches this service over plain authenticated HTTP via
 * `BROWSER_SERVICE_URL`, so it can equally run on Kubernetes, ECS, Fly, or a
 * VM — the host is a URL and a token, not an architectural commitment. Verify
 * Cloudflare Containers' cold-start latency and memory ceiling against your
 * traffic before settling on them for a workload that launches a browser.
 */
// export class BrowserService extends Cloudflare.Container<BrowserService>()(
//   "BrowserService",
//   {
//     context: `${import.meta.dirname}/../..`,
//     dockerfile: `${import.meta.dirname}/../../container/Dockerfile`,
//     instanceType: "standard-1"
//   }
// ) {}
