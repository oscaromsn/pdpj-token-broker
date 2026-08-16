import { Context, Effect, Layer, Redacted } from "effect"
import { HttpClient, HttpClientRequest } from "effect/unstable/http"
import type { ProcessNumber } from "../domain/ProcessNumber.ts"
import {
  ProcessQuery,
  ProcessQueryBlocked,
  ProcessQueryUnavailable,
  ProcessTokenRejected,
  type ProcessResult
} from "../ports/ProcessQuery.ts"

/** Base URL of the PDPJ process API, e.g. `https://portaldeservicos.pdpj.jus.br/api/v2/processos`. */
export class ProcessApiConfig extends Context.Service<ProcessApiConfig, {
  readonly baseUrl: string
}>()("broker/query/ProcessApiConfig") {}

/**
 * Browser-shaped headers, because the PDPJ gateway rejects requests that do
 * not look like the portal's own SPA. A bare `Bearer` gets a WAF 403; these
 * make a plain HTTP request pass — up to the point where the WAF also
 * fingerprints the TLS handshake, which no header can disguise. That residual
 * case is what the browser adapter exists for.
 */
const BROWSER_HEADERS: Record<string, string> = {
  "user-agent":
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
    "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
  accept: "application/json, text/plain, */*",
  "accept-language": "pt-BR,pt;q=0.9,en;q=0.8",
  origin: "https://portaldeservicos.pdpj.jus.br",
  referer: "https://portaldeservicos.pdpj.jus.br/",
  "sec-fetch-dest": "empty",
  "sec-fetch-mode": "cors",
  "sec-fetch-site": "same-origin"
}

/** The application's refusal message, seen live for a sealed process. */
const NO_ACCESS = /n[ãa]o possui acesso/i

/** A WAF/gateway block renders an HTML error page, never the API's JSON. */
const looksLikeGateway = (body: string): boolean =>
  /<html|<!doctype html|Forbidden<|cloudflare|Request Rejected/i.test(body)

const messageFrom = (body: string): string => {
  try {
    return (JSON.parse(body) as { message?: string }).message ?? body.slice(0, 200)
  } catch {
    return body.slice(0, 200)
  }
}

/**
 * `ProcessQuery` over plain HTTP.
 *
 * The classification is the substance here, and it comes straight from the
 * live run: the outcome is read from the *body*, not the status code, because
 * PDPJ returns "não possui acesso" as a 401 for one process and a 403 for a
 * filtered list. Conflating that with a genuinely rejected token — a 401 with
 * no such message — would tell a caller to re-authenticate when the real
 * problem is standing, or send it retrying through a browser that would be
 * refused just the same.
 */
export class HttpProcessQuery {
  static readonly layer: Layer.Layer<
    ProcessQuery,
    never,
    HttpClient.HttpClient | ProcessApiConfig
  > = Layer.effect(
    ProcessQuery,
    Effect.gen(function*() {
      const config = yield* ProcessApiConfig
      const client = yield* HttpClient.HttpClient

      const byNumber = Effect.fn("HttpProcessQuery.byNumber")(
        function*(token: Redacted.Redacted<string>, numero: ProcessNumber) {
          const response = yield* client.execute(
            HttpClientRequest.get(`${config.baseUrl}/${numero}`).pipe(
              HttpClientRequest.setHeaders(BROWSER_HEADERS),
              HttpClientRequest.bearerToken(Redacted.value(token))
            )
          ).pipe(
            Effect.mapError((cause) =>
              // A reset connection is the WAF's other tell; treat it as a block
              // so the caller escalates to a browser rather than giving up.
              new ProcessQueryBlocked({ detail: `transport failed: ${String(cause)}` })
            )
          )

          const body = yield* response.text.pipe(Effect.orElseSucceed(() => ""))

          if (response.status === 200) {
            return { _tag: "Found", json: body } satisfies ProcessResult
          }

          // A gateway HTML page means the request never reached the app — a WAF
          // block, retryable through a browser. Check this before the status
          // codes, since the WAF also uses 403.
          if (looksLikeGateway(body)) {
            return yield* new ProcessQueryBlocked({
              detail: `gateway blocked the request (HTTP ${response.status})`
            })
          }

          // A valid token with no standing in this case. Not a transport
          // problem and not retryable — a browser would be refused too.
          if (NO_ACCESS.test(body)) {
            return { _tag: "NoStanding", message: messageFrom(body) } satisfies ProcessResult
          }

          if (response.status === 404) {
            return { _tag: "NotFound" } satisfies ProcessResult
          }

          if (response.status === 401 || response.status === 403) {
            // 401/403 without the access message = the token itself was
            // rejected (expired/malformed), which is terminal for the caller.
            return yield* new ProcessTokenRejected({
              detail: `token rejected (HTTP ${response.status})`
            })
          }

          if (response.status >= 500) {
            return yield* new ProcessQueryUnavailable({
              detail: `PDPJ returned ${response.status}`
            })
          }

          return yield* new ProcessQueryUnavailable({
            detail: `unexpected status ${response.status}: ${body.slice(0, 160)}`
          })
        }
      )

      return ProcessQuery.of({ byNumber })
    })
  )
}
