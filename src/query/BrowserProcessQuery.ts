import { Effect, Layer, Redacted } from "effect"
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http"
import { BrowserServiceConfig } from "../adapters/browser/ContainerBrowserLogin.ts"
import type { ProcessNumber } from "../domain/ProcessNumber.ts"
import {
  ProcessQuery,
  ProcessQueryBlocked,
  ProcessQueryUnavailable,
  ProcessTokenRejected,
  type ProcessResult
} from "../ports/ProcessQuery.ts"
import { ProcessApiConfig } from "./HttpProcessQuery.ts"
import { BrowserQueryReply } from "./BrowserQueryProtocol.ts"

const NO_ACCESS = /n[ãa]o possui acesso/i
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
 * `ProcessQuery` that runs the fetch *inside* the browser container.
 *
 * This is the WAF-proof transport. The container issues the request from a
 * real Chromium page, so it carries the browser's own TLS fingerprint and
 * origin — the thing that made the identical query succeed live from a browser
 * while a plain HTTP client got a gateway 403. It is slower and heavier, which
 * is why it is the fallback rather than the default.
 *
 * The response classification is identical to the HTTP adapter's, on purpose:
 * whether the query went over plain HTTP or through a page, "não possui
 * acesso" still means no standing and a 200 still means found. A gateway page
 * coming back *here* is different, though — the WAF-proof path being blocked is
 * a real outage, not something to escalate further, so it surfaces as
 * unavailable rather than as another retryable block.
 */
export class BrowserProcessQuery {
  static readonly layer: Layer.Layer<
    ProcessQuery,
    never,
    HttpClient.HttpClient | BrowserServiceConfig | ProcessApiConfig
  > = Layer.effect(
    ProcessQuery,
    Effect.gen(function*() {
      const browser = yield* BrowserServiceConfig
      const api = yield* ProcessApiConfig
      const client = yield* HttpClient.HttpClient

      const byNumber = Effect.fn("BrowserProcessQuery.byNumber")(
        function*(token: Redacted.Redacted<string>, numero: ProcessNumber) {
          const response = yield* client.execute(
            HttpClientRequest.post(`${browser.baseUrl}/query`).pipe(
              HttpClientRequest.bearerToken(Redacted.value(browser.authToken)),
              HttpClientRequest.bodyJsonUnsafe({
                accessToken: Redacted.value(token),
                url: `${api.baseUrl}/${numero}`
              })
            )
          ).pipe(
            Effect.timeoutOrElse({
              duration: browser.timeoutMillis,
              orElse: () =>
                Effect.fail(new ProcessQueryUnavailable({ detail: "browser container timed out" }))
            }),
            Effect.mapError((cause) =>
              cause._tag === "ProcessQueryUnavailable"
                ? cause
                : new ProcessQueryUnavailable({ detail: "browser container unreachable", cause })
            )
          )

          if (response.status !== 200) {
            return yield* new ProcessQueryUnavailable({
              detail: `browser container returned ${response.status}`
            })
          }

          const reply = yield* HttpClientResponse.schemaBodyJson(BrowserQueryReply)(response).pipe(
            Effect.mapError((cause) =>
              new ProcessQueryUnavailable({ detail: "browser container sent an unreadable reply", cause })
            )
          )

          if (reply.status === 200) {
            return { _tag: "Found", json: reply.body } satisfies ProcessResult
          }
          if (NO_ACCESS.test(reply.body)) {
            return { _tag: "NoStanding", message: messageFrom(reply.body) } satisfies ProcessResult
          }
          if (reply.status === 404) {
            return { _tag: "NotFound" } satisfies ProcessResult
          }
          if (looksLikeGateway(reply.body)) {
            // The browser path itself was blocked — the WAF-proof transport is
            // down, which is an outage, not something to escalate past.
            return yield* new ProcessQueryUnavailable({
              detail: "gateway blocked even the browser request"
            })
          }
          if (reply.status === 401 || reply.status === 403) {
            return yield* new ProcessTokenRejected({
              detail: `token rejected (HTTP ${reply.status})`
            })
          }
          return yield* new ProcessQueryUnavailable({
            detail: `unexpected status ${reply.status}`
          })
        }
      )

      return ProcessQuery.of({ byNumber })
    })
  )
}
