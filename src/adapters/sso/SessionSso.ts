import { Context, Effect, Layer, Option, Redacted } from "effect"
import { HttpClient } from "effect/unstable/http"
import { InvalidPassword, SsoUnavailable } from "../../domain/Errors.ts"
import type { Credential, TokenSet } from "../../domain/Model.ts"
import { SsoClient } from "../../ports/SsoClient.ts"
import { SessionStore } from "../../ports/SessionStore.ts"
import { exchange } from "./tokenExchange.ts"

/** Where the realm lives and who we claim to be. Same client as the browser flow. */
export class SessionSsoConfig extends Context.Service<SessionSsoConfig, {
  readonly realmUrl: string
  readonly clientId: string
}>()("broker/adapters/sso/SessionSsoConfig") {}

/**
 * `SsoClient` for gov.br-federated accounts, which have no local password.
 *
 * A gov.br account cannot be logged in headlessly — the identity lives at
 * gov.br, behind its own SSO and 2FA. But a token minted from a real gov.br
 * session carries a **refresh token**, and that refresh token renews access
 * silently, without a second gov.br login, for as long as it stays valid.
 *
 * So this adapter never "logs in" in the password sense. It is seeded once,
 * out of band, with a refresh token captured from a genuine gov.br session
 * (see `scripts/renew-session.ts`), and its whole job is to keep that alive:
 *
 *   - `refresh` performs the standard refresh grant.
 *   - `login` — reached by the broker on a cold cache — reads the stored
 *     refresh token and refreshes from it. There is no password to try.
 *
 * The subtlety is rotation. Keycloak issues a *new* refresh token on every use
 * and retires the old one, so the freshly issued token is persisted back to
 * the `SessionStore` immediately. Miss that write and the next cold start
 * presents a token the SSO has already invalidated.
 *
 * When the refresh token finally expires — the gov.br session reaches its max
 * lifetime — there is nothing to fall back to. That surfaces as a terminal
 * `InvalidPassword` (the broker's "re-enroll this credential" signal, reused
 * here to mean "re-capture the gov.br session"), never as a retryable error,
 * so the breaker does not spin on a session that is simply over.
 */
export class SessionSso {
  static readonly layer: Layer.Layer<
    SsoClient,
    never,
    HttpClient.HttpClient | SessionSsoConfig | SessionStore
  > = Layer.effect(
    SsoClient,
    Effect.gen(function*() {
      const config = yield* SessionSsoConfig
      const store = yield* SessionStore
      const client = yield* HttpClient.HttpClient

      /** The refresh grant, plus the mandatory persist-the-rotated-token step. */
      const refreshAndRotate = Effect.fn("SessionSso.refreshAndRotate")(
        function*(credential: Credential, refreshToken: Redacted.Redacted<string>) {
          const tokens = yield* exchange(client, config.realmUrl, {
            grant_type: "refresh_token",
            refresh_token: Redacted.value(refreshToken),
            client_id: config.clientId
          })

          // Persist the rotated refresh token before returning. If Keycloak
          // rotated it (the default) the old one is now dead, so a crash
          // between here and the next call would strand the session on a
          // retired token.
          if (tokens.refreshToken !== undefined) {
            yield* store.put(credential.tenantId, credential.id, tokens.refreshToken).pipe(
              Effect.mapError((cause) =>
                new SsoUnavailable({ detail: "could not persist rotated refresh token", cause })
              )
            )
          }

          return tokens
        }
      )

      const login = Effect.fn("SessionSso.login")(function*(credential: Credential) {
        const stored = yield* store.get(credential.tenantId, credential.id).pipe(
          Effect.mapError((cause) =>
            new SsoUnavailable({ detail: "session store unavailable", cause })
          )
        )

        if (Option.isNone(stored)) {
          // No session on file: this account was never captured, or its
          // session was cleared. Terminal — there is no password to fall back
          // to, and retrying cannot conjure a session.
          return yield* new InvalidPassword({
            credentialId: credential.id,
            detail: "no gov.br session on file — capture one with renew-session"
          })
        }

        const result = yield* Effect.result(refreshAndRotate(credential, stored.value))
        if (result._tag === "Success") return result.success

        // A refused refresh means the gov.br session is over. Clear it so the
        // stored state stops lying, and report it as terminal.
        yield* store.clear(credential.tenantId, credential.id).pipe(Effect.ignore)
        return yield* new InvalidPassword({
          credentialId: credential.id,
          detail: "gov.br session expired — re-capture it with renew-session"
        })
      })

      const refresh = Effect.fn("SessionSso.refresh")(
        function*(refreshToken: Redacted.Redacted<string>) {
          return yield* exchange(client, config.realmUrl, {
            grant_type: "refresh_token",
            refresh_token: Redacted.value(refreshToken),
            client_id: config.clientId
          })
        }
      )

      return SsoClient.of({
        login: (credential: Credential): Effect.Effect<TokenSet, InvalidPassword | SsoUnavailable> =>
          login(credential),
        refresh
      })
    })
  )
}
