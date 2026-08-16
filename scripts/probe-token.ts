import { Effect } from "effect"
import { FetchHttpClient, HttpClient, HttpClientRequest } from "effect/unstable/http"
import { PDPJ_BROWSER_HEADERS } from "./pdpjHeaders.ts"

/**
 * Diagnostics for a PDPJ access token captured by hand from a browser session.
 *
 * A gov.br-federated account cannot be logged in headlessly — that is settled.
 * So the token is obtained interactively, once, and pasted here. This script
 * then answers the questions a captured token can settle without any further
 * login:
 *
 *   1. Is the token well-formed and unexpired?
 *   2. Does PDPJ honour it for process queries?
 *   3. Does it reach the API-access programme (gestao-clientes)?
 *   4. What does it say for the target process?
 *
 * Read-only. It never sends the token anywhere but PDPJ's own hosts, and never
 * logs the token itself.
 *
 * Usage:
 *   PDPJ_TOKEN="eyJ..." bun scripts/probe-token.ts [--processo 0801429-56.2022.4.05.8201]
 */

const PROCESSOS = "https://portaldeservicos.pdpj.jus.br/api/v2/processos"
const CATALOGO = "https://gateway.cloud.pje.jus.br/gestao-clientes/api/v1/catalogo-apis"
const DEFAULT_PROCESSO = "0801429-56.2022.4.05.8201"

const flag = (name: string): string | undefined => {
  const i = process.argv.indexOf(`--${name}`)
  return i === -1 ? undefined : process.argv[i + 1]
}

let step = 0
const begin = (what: string) => process.stderr.write(`\n[${++step}] ${what}\n`)
const ok = (d: string) => process.stderr.write(`    ok — ${d}\n`)
const bad = (d: string) => process.stderr.write(`    FAILED — ${d}\n`)
const hint = (d: string) => process.stderr.write(`    → ${d}\n`)

const token = process.env["PDPJ_TOKEN"]
if (token === undefined || token.length === 0) {
  process.stderr.write("error: PDPJ_TOKEN is required (capture it from the browser — see below)\n")
  process.exit(1)
}

/** Decode a JWT payload without verifying — we only want its claims for display. */
const claims = (jwt: string): Record<string, unknown> | undefined => {
  const part = jwt.split(".")[1]
  if (part === undefined) return undefined
  try {
    const json = atob(part.replace(/-/g, "+").replace(/_/g, "/"))
    return JSON.parse(json) as Record<string, unknown>
  } catch {
    return undefined
  }
}

const program = Effect.gen(function*() {
  const client = yield* HttpClient.HttpClient
  const authed = (req: HttpClientRequest.HttpClientRequest) =>
    client.execute(
      // The PDPJ gateway WAF rejects non-browser requests; see pdpjHeaders.ts.
      HttpClientRequest.bearerToken(HttpClientRequest.setHeaders(req, PDPJ_BROWSER_HEADERS), token)
    ).pipe(
      Effect.flatMap((r) =>
        r.text.pipe(Effect.orElseSucceed(() => ""), Effect.map((body) => ({ status: r.status, body })))
      ),
      Effect.catch((cause) => Effect.succeed({ status: 0, body: String(cause) }))
    )

  // 1. Shape and expiry — a pasted token is often truncated or already stale.
  begin("Inspect the token")
  const c = claims(token)
  if (c === undefined) {
    bad("not a decodable JWT — did the whole value get copied?")
    return false
  }
  const exp = typeof c["exp"] === "number" ? c["exp"] : 0
  const secondsLeft = exp - Math.floor(Date.now() / 1000)
  const subject = c["preferred_username"] ?? c["cpf"] ?? c["sub"] ?? "?"
  ok(`subject=${String(subject)}, issuer=${String(c["iss"] ?? "?")}`)
  if (secondsLeft <= 0) {
    bad(`expired ${-secondsLeft}s ago — capture a fresh one`)
    return false
  }
  ok(`valid for ~${secondsLeft}s (~${Math.round(secondsLeft / 60)} min)`)

  // 2. Does PDPJ accept it at all?
  begin("Query PDPJ (list endpoint, proves the token is honoured)")
  const list = yield* authed(HttpClientRequest.get(PROCESSOS).pipe(HttpClientRequest.acceptJson))
  if (list.status === 401) {
    bad("PDPJ rejected the token (401) — stale, or the wrong Bearer was copied")
    return false
  }
  if (list.status === 0) {
    bad(`could not reach PDPJ: ${list.body.slice(0, 160)}`)
    return false
  }
  ok(`PDPJ honoured the token (HTTP ${list.status})`)

  // 3. The API-access programme — does this user's token reach it?
  begin("Reach the API programme catalog (gestao-clientes)")
  const cat = yield* authed(HttpClientRequest.get(`${CATALOGO}?page=0&size=200`))
  if (cat.status === 200) {
    let names: Array<string> = []
    try {
      const parsed = JSON.parse(cat.body) as unknown
      const items = Array.isArray(parsed)
        ? parsed
        : ((parsed as { content?: Array<unknown>; result?: Array<unknown> }).content ??
          (parsed as { result?: Array<unknown> }).result ?? [])
      names = (items as Array<Record<string, unknown>>)
        .map((a) => String(a["sigla"] ?? a["siglaApi"] ?? a["nome"] ?? a["nomeApi"] ?? "?"))
        .filter((n) => n !== "?")
    } catch { /* leave names empty */ }
    ok(`catalog reachable — ${names.length} API(s) listed`)
    const judicial = names.filter((n) => /processo|cabecalho|datalake|judicial/i.test(n))
    if (judicial.length > 0) {
      hint(`process-related APIs in the catalog: ${judicial.join(", ")}`)
    }
    process.stderr.write(`    catalog: ${names.slice(0, 30).join(", ")}\n`)
  } else {
    bad(`catalog returned ${cat.status}`)
    hint("expected if this personal token has no API-programme access — that path needs a granted client")
  }

  // 4. The actual target.
  const processo = flag("processo") ?? DEFAULT_PROCESSO
  const digits = processo.replace(/\D/g, "")
  begin(`Query the target process ${processo}`)
  const one = yield* authed(
    HttpClientRequest.get(`${PROCESSOS}/${digits}`).pipe(HttpClientRequest.acceptJson)
  )
  if (one.status === 200) {
    ok("PDPJ returned the process — this account HAS access")
    process.stderr.write("\n")
    process.stdout.write(one.body.slice(0, 4000) + "\n")
    return true
  }
  // The access-control refusal is keyed off the message, not the status: PDPJ
  // returns "Usuário ... não possui acesso" as a 401 for a single process (and
  // as a 403 for a filtered list). Both mean the same thing — a valid token
  // with no standing in this case — so the diagnosis follows the body.
  if (/n[ãa]o possui acesso/i.test(one.body)) {
    bad("valid token, but no standing in this case")
    hint("a sealed process is visible only to a party or counsel of record")
    hint(`PDPJ said: ${(JSON.parse(one.body) as { message?: string }).message ?? one.body.slice(0, 200)}`)
    return false
  }
  if (one.status === 401) {
    bad("PDPJ rejected the token (401) — stale, or the wrong Bearer was copied")
    return false
  }
  bad(`process query returned ${one.status}`)
  hint(one.body.slice(0, 300))
  return false
}).pipe(Effect.provide(FetchHttpClient.layer))

Effect.runPromise(program)
  .then((passed) => {
    process.stderr.write(passed ? "\nDONE — process retrieved\n" : "\nDONE — see hints above\n")
    process.exit(0)
  })
  .catch((error: unknown) => {
    process.stderr.write(`\nunexpected: ${String(error)}\n`)
    process.exit(1)
  })
