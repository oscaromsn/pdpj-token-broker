import { Effect, Redacted, Schema } from "effect"
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http"
import { SsoUnavailable } from "../../domain/Errors.ts"
import { TokenSet } from "../../domain/Model.ts"

/**
 * The Keycloak token-endpoint exchange, shared by every SSO adapter.
 *
 * Both the browser-login adapter and the session adapter end at the same
 * `POST /token` call and parse the same response; keeping that in one place
 * means the `expires_in` → absolute `expiresAt` conversion — the detail a
 * cache depends on to not serve a dead token — cannot drift between them.
 */

/** Only the fields any adapter actually relies on. */
const TokenResponse = Schema.Struct({
  access_token: Schema.String,
  refresh_token: Schema.optional(Schema.String),
  expires_in: Schema.Number
})

/**
 * POST a form to the realm's token endpoint and decode the result.
 *
 * `realmUrl` is the OIDC base (`.../protocol/openid-connect`); this appends
 * `/token`. The caller supplies the grant-specific form fields.
 */
export const exchange = (
  client: HttpClient.HttpClient,
  realmUrl: string,
  form: Record<string, string>
): Effect.Effect<TokenSet, SsoUnavailable> =>
  Effect.gen(function*() {
    const response = yield* client.execute(
      HttpClientRequest.post(`${realmUrl}/token`).pipe(HttpClientRequest.bodyUrlParams(form))
    ).pipe(Effect.mapError((cause) => new SsoUnavailable({ detail: "token endpoint unreachable", cause })))

    if (response.status !== 200) {
      const body = yield* response.text.pipe(Effect.orElseSucceed(() => ""))
      return yield* new SsoUnavailable({
        detail: `token endpoint returned ${response.status}: ${body.slice(0, 200)}`
      })
    }

    const payload = yield* HttpClientResponse.schemaBodyJson(TokenResponse)(response).pipe(
      Effect.mapError((cause) =>
        new SsoUnavailable({ detail: "token response was not the expected shape", cause })
      )
    )

    const now = yield* Effect.clockWith((clock) => clock.currentTimeMillis)

    return new TokenSet({
      accessToken: Redacted.make(payload.access_token),
      ...(payload.refresh_token === undefined
        ? {}
        : { refreshToken: Redacted.make(payload.refresh_token) }),
      // Absolute, not relative: a duration is only meaningful next to the
      // instant it was issued.
      expiresAt: now + payload.expires_in * 1000
    })
  })
