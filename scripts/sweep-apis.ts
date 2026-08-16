import { Effect } from "effect"
import { FetchHttpClient, HttpClient, HttpClientRequest } from "effect/unstable/http"
import { PDPJ_BROWSER_HEADERS } from "./pdpjHeaders.ts"

/**
 * Probes the CNJ/PDPJ production APIs a gov.br *user* token could plausibly
 * reach, and reports what each one says. Read-only GETs only.
 *
 * The point is to separate, empirically, three things the specs cannot tell
 * you for certain: which services accept this kind of token at all, which
 * accept it but refuse the data for lack of standing, and which need a
 * different credential entirely (a granted client, an API key).
 *
 *   PDPJ_TOKEN="eyJ..." bun scripts/sweep-apis.ts
 *
 * The token's CPF is read from its claims and sent as
 * `X-PDPJ-CPF-USUARIO-OPERADOR` where the spec requires it.
 */

const token = process.env["PDPJ_TOKEN"]
if (token === undefined || token.length === 0) {
  process.stderr.write("error: PDPJ_TOKEN is required (a fresh gov.br access token)\n")
  process.exit(1)
}

const claims = (jwt: string): Record<string, unknown> => {
  try {
    const part = jwt.split(".")[1] ?? ""
    return JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/"))) as Record<string, unknown>
  } catch {
    return {}
  }
}
const cpf = String(claims(token)["preferred_username"] ?? "")

/** Each probe is a GET that needs no path parameters, so it is safe to fire blind. */
interface Probe {
  readonly name: string
  readonly url: string
  readonly operator?: boolean // send X-PDPJ-CPF-USUARIO-OPERADOR
  readonly note?: string
}

const PROBES: ReadonlyArray<Probe> = [
  // Known-good control: the endpoint we already proved accepts this token.
  { name: "processos (v2) — controle", url: `https://portaldeservicos.pdpj.jus.br/api/v2/processos?cpfCnpjParte=${cpf}` },

  // PDPJ production gateway, JWT/bearer — the real candidates.
  { name: "datalake-processos", url: "https://api-processo-integracao.data-lake.pdpj.jus.br/processo-api/api/v1/processos", operator: true },
  { name: "cadastro-pessoas", url: `https://gateway.cloud.pje.jus.br/pessoas-api/api/v1/pessoas?cpfCnpj=${cpf}`, operator: true },
  { name: "bcadastros-divida-ativa", url: "https://gateway.cloud.pje.jus.br/bcadastrosconsulta/api/v1/dau/situacao-inscricao", operator: true },
  { name: "previdenciario", url: "https://gateway.cloud.pje.jus.br/previdenciario-api/pdpj/info" },
  { name: "gestao-clientes (catálogo)", url: "https://gateway.cloud.pje.jus.br/gestao-clientes/api/v1/catalogo-apis?page=0&size=5" },
  { name: "sngb-bens-apreendidos", url: "https://gateway.cloud.pje.jus.br/sngb/pdpj/info", operator: true },

  // Public / no-auth references — should answer even without the token; a
  // useful contrast for what "open" looks like.
  { name: "TPU classes (público)", url: "https://gateway.cloud.pje.jus.br/tpu/api/v1/publico/consulta/classes" },
  { name: "DJEN comunicações (público)", url: `https://comunicaapi.pje.jus.br/api/v1/comunicacao?numeroProcesso=00000000000000000000` },
  { name: "bnp-sempj info", url: "https://bnp-sempj.cloud.pje.jus.br/pdpj/info" }
]

const NO_ACCESS = /n[ãa]o possui acesso/i
const gateway = (b: string) => /<html|Forbidden<|cloudflare|Request Rejected/i.test(b)

const verdict = (status: number, body: string): string => {
  if (status === 200) return "✓ ACEITA o token (200)"
  if (status === 0) return "… sem resposta / bloqueado no transporte"
  if (gateway(body)) return "▲ WAF bloqueou (tentar via navegador)"
  if (NO_ACCESS.test(body)) return "◐ token OK, sem legitimidade no dado (não possui acesso)"
  if (status === 401) return "✕ 401 — token não aceito aqui (outra credencial)"
  if (status === 403) return "✕ 403 — proibido (cliente/perfil concedido)"
  if (status === 404) return "· 404 — sem dado (mas endpoint respondeu)"
  if (status === 400) return "· 400 — endpoint respondeu (faltou parâmetro)"
  return `? ${status}`
}

const program = Effect.gen(function*() {
  const client = yield* HttpClient.HttpClient
  process.stderr.write(`token de: ${cpf}\n\n`)

  for (const probe of PROBES) {
    const headers: Record<string, string> = {
      ...PDPJ_BROWSER_HEADERS,
      ...(probe.operator === true ? { "X-PDPJ-CPF-USUARIO-OPERADOR": cpf } : {})
    }
    const res = yield* client.execute(
      HttpClientRequest.get(probe.url).pipe(
        HttpClientRequest.setHeaders(headers),
        HttpClientRequest.bearerToken(token)
      )
    ).pipe(
      Effect.flatMap((r) => r.text.pipe(Effect.orElseSucceed(() => ""), Effect.map((b) => ({ status: r.status, body: b })))),
      Effect.catch((cause) => Effect.succeed({ status: 0, body: String(cause) }))
    )
    process.stderr.write(`${probe.name.padEnd(32)} ${verdict(res.status, res.body)}\n`)
  }
}).pipe(Effect.provide(FetchHttpClient.layer))

Effect.runPromise(program)
  .then(() => process.exit(0))
  .catch((e: unknown) => {
    process.stderr.write(`\nunexpected: ${String(e)}\n`)
    process.exit(1)
  })
