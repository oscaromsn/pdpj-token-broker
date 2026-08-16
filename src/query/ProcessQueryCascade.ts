import { Context, Effect, Layer, type Redacted } from "effect"
import type { ProcessNumber } from "../domain/ProcessNumber.ts"
import { ProcessQuery, type ProcessQueryError, type ProcessResult } from "../ports/ProcessQuery.ts"

/** Tags for the two ProcessQuery implementations the cascade sits over. */
export class HttpQuery extends Context.Service<HttpQuery, ProcessQuery["Service"]>()(
  "broker/query/HttpQuery"
) {}
export class BrowserQuery extends Context.Service<BrowserQuery, ProcessQuery["Service"]>()(
  "broker/query/BrowserQuery"
) {}

/**
 * `ProcessQuery` that tries plain HTTP first and escalates to the browser
 * transport only when the gateway blocks the cheap path.
 *
 * The escalation rule is the point, and it is the same discipline as the login
 * cascade: fall back only on the signal that a *different transport* could fix.
 * `ProcessQueryBlocked` means the WAF rejected the request shape — a browser
 * can get through, so retry there. Everything else is passed straight up: a
 * `NoStanding` result would be refused by the browser identically, and a
 * `ProcessTokenRejected` is a token problem no transport changes. Retrying
 * those through the browser would only burn a slow, expensive request to reach
 * the same answer.
 */
export class ProcessQueryCascade {
  static readonly layer: Layer.Layer<ProcessQuery, never, HttpQuery | BrowserQuery> = Layer.effect(
    ProcessQuery,
    Effect.gen(function*() {
      const http = yield* HttpQuery
      const browser = yield* BrowserQuery

      const byNumber = Effect.fn("ProcessQueryCascade.byNumber")(
        function*(
          token: Redacted.Redacted<string>,
          numero: ProcessNumber
        ): Effect.fn.Return<ProcessResult, ProcessQueryError> {
          return yield* http.byNumber(token, numero).pipe(
            Effect.catchTag("ProcessQueryBlocked", () => browser.byNumber(token, numero))
          )
        }
      )

      return ProcessQuery.of({ byNumber })
    })
  )
}
