import { Context, Effect, Layer, Redacted } from "effect"
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http"
import { InvalidPassword, InvalidTotp, SsoUnavailable } from "../../domain/Errors.ts"
import { type Credential, TokenSet } from "../../domain/Model.ts"
import { BrowserLogin } from "../../ports/SsoClient.ts"
import { BrowserLoginReply } from "./Protocol.ts"

/** Where the browser container lives, and the token used to reach it. */
export class BrowserServiceConfig extends Context.Service<BrowserServiceConfig, {
  /** Base URL of the container, e.g. `https://browser.internal`. */
  readonly baseUrl: string
  /** Shared secret; the container rejects requests without it. */
  readonly authToken: Redacted.Redacted<string>
  /** A real browser login is slow — a minute is not unusual. */
  readonly timeoutMillis: number
}>()("broker/adapters/browser/BrowserServiceConfig") {}

/**
 * `BrowserLogin` implemented as a call to the browser container.
 *
 * Playwright cannot run inside a Worker, so the fallback lives in a container
 * and the Worker reaches it over HTTP. Keeping that split behind the port is
 * what let phases 1–4 ship with no browser at all: the broker has always
 * escalated to `BrowserLogin` on `ChallengeRequired`, and only the wiring
 * changes here.
 *
 * This adapter is deliberately thin. It does not retry — the broker's circuit
 * breaker owns that decision, and a retry here would multiply attempts against
 * the SSO behind the breaker's back.
 */
export class ContainerBrowserLogin {
  static readonly layer: Layer.Layer<
    BrowserLogin,
    never,
    HttpClient.HttpClient | BrowserServiceConfig
  > = Layer.effect(
    BrowserLogin,
    Effect.gen(function*() {
      const config = yield* BrowserServiceConfig
      const client = yield* HttpClient.HttpClient

      const login = Effect.fn("ContainerBrowserLogin.login")(function*(credential: Credential) {
        const response = yield* client.execute(
          HttpClientRequest.post(`${config.baseUrl}/login`).pipe(
            HttpClientRequest.bearerToken(Redacted.value(config.authToken)),
            HttpClientRequest.bodyJsonUnsafe({
              cpf: credential.cpf,
              password: Redacted.value(credential.password),
              ...(credential.totpSeed === undefined
                ? {}
                : { totpSeed: Redacted.value(credential.totpSeed) })
            })
          )
        ).pipe(
          // Map transport failures first, so the only error left for the
          // timeout to sit alongside is already an `SsoUnavailable`.
          Effect.mapError((cause) =>
            new SsoUnavailable({ detail: "browser container unreachable", cause })
          ),
          Effect.timeoutOrElse({
            duration: config.timeoutMillis,
            orElse: () =>
              Effect.fail(new SsoUnavailable({ detail: "browser container timed out" }))
          })
        )

        if (response.status !== 200) {
          return yield* new SsoUnavailable({
            detail: `browser container returned ${response.status}`
          })
        }

        const reply = yield* HttpClientResponse.schemaBodyJson(BrowserLoginReply)(response).pipe(
          Effect.mapError((cause) =>
            new SsoUnavailable({ detail: "browser container sent an unreadable reply", cause })
          )
        )

        switch (reply._tag) {
          case "InvalidPassword":
            // Terminal, exactly as on the HTTP path: a browser retry would
            // spend the account's lockout budget for nothing.
            return yield* new InvalidPassword({
              credentialId: credential.id,
              detail: reply.detail
            })
          case "InvalidTotp":
            return yield* new InvalidTotp({
              credentialId: credential.id,
              detail: reply.detail
            })
          case "Failed":
            return yield* new SsoUnavailable({ detail: reply.detail })
          case "Success":
            return new TokenSet({
              accessToken: Redacted.make(reply.accessToken),
              ...(reply.refreshToken === undefined
                ? {}
                : { refreshToken: Redacted.make(reply.refreshToken) }),
              expiresAt: reply.expiresAt
            })
        }
      })

      return BrowserLogin.of({ login })
    })
  )
}
