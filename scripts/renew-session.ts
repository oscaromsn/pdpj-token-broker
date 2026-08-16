import { Effect, Redacted } from "effect"
import { FetchHttpClient, HttpClient } from "effect/unstable/http"
import { exchange } from "../src/adapters/sso/tokenExchange.ts"
import { PDPJ_BROWSER_HEADERS } from "./pdpjHeaders.ts"

/**
 * Seed and exercise a gov.br session for the broker.
 *
 * A gov.br account cannot be logged in headlessly — the identity lives at
 * gov.br behind its own SSO and 2FA. So the session is captured once,
 * interactively, and from then on the broker keeps it alive by refresh. This
 * tool is the bridge between that one interactive login and the running
 * service, and the proof that the refresh path works against the live SSO.
 *
 * It takes a **refresh token** captured from a real gov.br session and:
 *   1. refreshes it (the exact grant the SessionSso adapter performs),
 *   2. queries PDPJ with the fresh access token, proving the token is real,
 *   3. prints the rotated refresh token — the value to store, or to feed the
 *      next run.
 *
 * Run it repeatedly and it walks the session forward one rotation at a time,
 * which is exactly what the broker does in production.
 *
 * ── Capturing the refresh token (once, in a browser) ──
 *   1. Open https://portaldeservicos.pdpj.jus.br and log in with gov.br.
 *   2. DevTools → Network → filter "token".
 *   3. Find the POST to .../openid-connect/token whose response is JSON.
 *      Copy `refresh_token` from that response body.
 *   (The access token in the Authorization header is NOT enough — it has no
 *    refresh token attached, so it cannot be renewed.)
 *
 * ── Usage ──
 *   PDPJ_REFRESH_TOKEN="eyJ..." bun scripts/renew-session.ts
 */

const REALM = "https://sso.cloud.pje.jus.br/auth/realms/pje/protocol/openid-connect"
const CLIENT_ID = "portalexterno-frontend"
const PROCESSOS = "https://portaldeservicos.pdpj.jus.br/api/v2/processos"

const refreshToken = process.env["PDPJ_REFRESH_TOKEN"]
if (refreshToken === undefined || refreshToken.length === 0) {
  process.stderr.write("error: PDPJ_REFRESH_TOKEN is required (see the file header for capture steps)\n")
  process.exit(1)
}

let step = 0
const begin = (what: string) => process.stderr.write(`\n[${++step}] ${what}\n`)
const ok = (d: string) => process.stderr.write(`    ok — ${d}\n`)
const bad = (d: string) => process.stderr.write(`    FAILED — ${d}\n`)
const hint = (d: string) => process.stderr.write(`    → ${d}\n`)

const claims = (jwt: string): Record<string, unknown> | undefined => {
  const part = jwt.split(".")[1]
  if (part === undefined) return undefined
  try {
    return JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/"))) as Record<string, unknown>
  } catch {
    return undefined
  }
}

const program = Effect.gen(function*() {
  const client = yield* HttpClient.HttpClient

  begin("Refresh the gov.br session (the grant SessionSso performs)")
  const result = yield* Effect.result(
    exchange(client, REALM, {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID
    })
  )

  if (result._tag === "Failure") {
    bad(result.failure.detail)
    hint(
      "an expired or already-rotated refresh token is the usual cause — the " +
        "SSO issues a new one on every use and retires the old. Capture a fresh one."
    )
    return false
  }

  const tokens = result.success
  const access = Redacted.value(tokens.accessToken)
  const c = claims(access)
  const secondsLeft = Math.round((tokens.expiresAt - Date.now()) / 1000)
  ok(`fresh access token for ${String(c?.["preferred_username"] ?? c?.["sub"] ?? "?")}, ~${secondsLeft}s`)

  begin("Query PDPJ with the fresh token (proves it is real)")
  const cpf = typeof c?.["preferred_username"] === "string" ? c["preferred_username"] : undefined
  const url = cpf === undefined ? PROCESSOS : `${PROCESSOS}?cpfCnpjParte=${cpf}`
  const response = yield* client.get(url, {
    // The PDPJ gateway blocks non-browser requests; a bare Bearer alone gets a
    // WAF 403. See pdpjHeaders.ts.
    headers: { ...PDPJ_BROWSER_HEADERS, authorization: `Bearer ${access}` }
  }).pipe(
    Effect.flatMap((r) => r.text.pipe(Effect.orElseSucceed(() => ""), Effect.map((b) => ({ status: r.status, body: b })))),
    Effect.catch((cause) => Effect.succeed({ status: 0, body: String(cause) }))
  )

  if (response.status === 200) {
    ok("PDPJ honoured the refreshed token")
    try {
      const parsed = JSON.parse(response.body) as { total?: number }
      if (typeof parsed.total === "number") hint(`${parsed.total} process(es) visible to this account`)
    } catch { /* not the list shape; fine */ }
  } else {
    bad(`PDPJ returned ${response.status}`)
    hint(response.body.slice(0, 200))
  }

  begin("Rotated refresh token — store this")
  if (tokens.refreshToken === undefined) {
    hint("the SSO returned no new refresh token; the old one may still be valid")
  } else {
    process.stderr.write("    (the seed you passed is now retired; the value below replaces it)\n\n")
    process.stdout.write(Redacted.value(tokens.refreshToken) + "\n")
  }
  return response.status === 200
}).pipe(Effect.provide(FetchHttpClient.layer))

Effect.runPromise(program)
  .then((passed) => {
    process.stderr.write(passed ? "\nDONE — session renewed and verified\n" : "\nDONE — see hints above\n")
    process.exit(passed ? 0 : 1)
  })
  .catch((error: unknown) => {
    process.stderr.write(`\nunexpected: ${String(error)}\n`)
    process.exit(1)
  })
