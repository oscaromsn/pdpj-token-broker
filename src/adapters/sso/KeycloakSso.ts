import { Context, Effect, Layer, Redacted, Ref, Schema } from "effect"
import { Cookies, FetchHttpClient, HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http"
import {
  ChallengeRequired,
  InvalidPassword,
  InvalidTotp,
  SsoUnavailable
} from "../../domain/Errors.ts"
import { type Credential, TokenSet } from "../../domain/Model.ts"
import { exchange as exchangeToken } from "./tokenExchange.ts"
import { SsoClient } from "../../ports/SsoClient.ts"
import { TotpGenerator } from "../../ports/TotpGenerator.ts"

/** Where the realm lives and who we claim to be. */
export class SsoConfig extends Context.Service<SsoConfig, {
  /** e.g. `https://sso.cloud.pje.jus.br/auth/realms/pje/protocol/openid-connect` */
  readonly realmUrl: string
  readonly clientId: string
  readonly redirectUri: string
}>()("broker/adapters/sso/SsoConfig") {}

/**
 * Markers that identify each page in the login flow.
 *
 * Scraping is unavoidable — Keycloak's browser flow has no API — so the
 * markers are kept together here rather than scattered through the code. When
 * CNJ restyles the login page, this block is the thing that needs updating,
 * and the fixture tests are what will tell you.
 */
const FORM_ACTION = /action="([^"]*login-actions\/authenticate[^"]*)"/
const HAS_PASSWORD_FIELD = /name="password"/
const HAS_OTP_FIELD = /name="otp"/
const CHALLENGE_MARKERS = /g-recaptcha|cf-turnstile|hcaptcha|data-sitekey/i
const FEEDBACK_TEXT = /class="[^"]*(?:kc-feedback-text|input-error)[^"]*"[^>]*>([^<]{1,200})</

const unescapeHtml = (value: string): string =>
  value
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&#39;/g, "'")

/** Keycloak's own error text, if it rendered one. Used only for diagnostics. */
const feedbackFrom = (html: string): string => {
  const match = FEEDBACK_TEXT.exec(html)
  return match?.[1]?.trim() ?? "no message rendered"
}

/**
 * `SsoClient` over Keycloak's browser flow.
 *
 * The password grant this would naturally use is disabled for
 * `portalexterno-frontend` ("Client not allowed for direct access grants"),
 * so the only route to a token is the `authorization_code` dance a browser
 * performs: fetch the form, post credentials, answer the second factor,
 * follow the redirect, exchange the code. This adapter does exactly that over
 * plain HTTP — no browser — which is fast and cheap right up until the day
 * CNJ adds a challenge, at which point it reports `ChallengeRequired` and the
 * broker escalates rather than guessing.
 */
export class KeycloakSso {
  static readonly layer: Layer.Layer<
    SsoClient,
    never,
    HttpClient.HttpClient | SsoConfig | TotpGenerator
  > = Layer.effect(
    SsoClient,
    Effect.gen(function*() {
      const config = yield* SsoConfig
      const totp = yield* TotpGenerator

      // Redirects are followed manually: the authorization code arrives in a
      // `Location` header, and a client that transparently follows it would
      // chase the redirect to the SPA and throw the code away.
      //
      // This alone is not enough in production — `fetch` follows redirects
      // itself, below this layer — which is why `KeycloakSso.layerHttp` also
      // sets `redirect: "manual"`. Both are required.
      const baseClient = (yield* HttpClient.HttpClient).pipe(HttpClient.followRedirects(0))

      /**
       * A client with its own cookie jar.
       *
       * Keycloak threads `AUTH_SESSION_ID` and `KC_RESTART` cookies through
       * the flow, so the steps must share a jar — but only with each other.
       * A jar shared across logins would let one tenant's session cookies
       * ride along with another tenant's request, which is a cross-tenant
       * authentication bug, so a fresh one is built per attempt.
       */
      const isolatedClient = Effect.gen(function*() {
        const jar = yield* Ref.make(Cookies.empty)
        return baseClient.pipe(HttpClient.withCookiesRef(jar))
      })

      const unavailable = (detail: string) => (cause: unknown) =>
        new SsoUnavailable({ detail, cause })

      /** Read a response body, mapping transport failures to a transient error. */
      const bodyOf = Effect.fn("KeycloakSso.bodyOf")(
        function*(response: HttpClientResponse.HttpClientResponse) {
          return yield* response.text.pipe(
            Effect.mapError(unavailable("could not read SSO response body"))
          )
        }
      )

      /** A 5xx, or anything that is not a page we know how to read. */
      const assertUsable = Effect.fn("KeycloakSso.assertUsable")(
        function*(response: HttpClientResponse.HttpClientResponse) {
          if (response.status >= 500) {
            return yield* new SsoUnavailable({
              detail: `SSO returned ${response.status}`
            })
          }
        }
      )

      /** Pull `code` out of the fragment or query of a redirect target. */
      const codeFrom = (location: string): string | undefined =>
        /[#&?]code=([^&]+)/.exec(location)?.[1]

      // The token-endpoint call is shared with the session adapter; only the
      // grant-specific form fields differ per call site.
      const exchange = (client: HttpClient.HttpClient, form: Record<string, string>) =>
        exchangeToken(client, config.realmUrl, form)

      const login = Effect.fn("KeycloakSso.login")(function*(credential: Credential) {
        const client = yield* isolatedClient

        // 1. Fetch the login form to obtain the one-shot action URL, which
        //    carries session_code, execution and tab_id.
        const authUrl = `${config.realmUrl}/auth`
        const start = yield* client.get(authUrl, {
          urlParams: {
            client_id: config.clientId,
            redirect_uri: config.redirectUri,
            response_type: "code",
            response_mode: "fragment",
            scope: "openid",
            state: crypto.randomUUID(),
            nonce: crypto.randomUUID()
          }
        }).pipe(Effect.mapError(unavailable("SSO authorize endpoint unreachable")))

        yield* assertUsable(start)
        const loginPage = yield* bodyOf(start)

        if (CHALLENGE_MARKERS.test(loginPage)) {
          return yield* new ChallengeRequired({
            detail: "login page presented a captcha"
          })
        }

        const action = FORM_ACTION.exec(loginPage)?.[1]
        if (action === undefined) {
          // No form and no code means the page is not what we know how to
          // drive — report it as unavailable rather than blindly posting.
          return yield* new SsoUnavailable({
            detail: "login form not found on the SSO page"
          })
        }

        // 2. Post the credentials to that action.
        const afterPassword = yield* client.execute(
          HttpClientRequest.post(unescapeHtml(action)).pipe(
            HttpClientRequest.bodyUrlParams({
              username: credential.cpf,
              password: Redacted.value(credential.password),
              credentialId: ""
            })
          )
        ).pipe(Effect.mapError(unavailable("SSO login post failed")))

        yield* assertUsable(afterPassword)

        // A redirect here means the server skipped 2FA entirely.
        const directLocation = afterPassword.headers["location"]
        if (directLocation !== undefined) {
          const code = codeFrom(directLocation)
          if (code === undefined) {
            return yield* new SsoUnavailable({
              detail: "SSO redirected without an authorization code"
            })
          }
          return yield* exchange(client, {
            grant_type: "authorization_code",
            code,
            client_id: config.clientId,
            redirect_uri: config.redirectUri
          })
        }

        const afterPasswordBody = yield* bodyOf(afterPassword)

        if (CHALLENGE_MARKERS.test(afterPasswordBody)) {
          return yield* new ChallengeRequired({ detail: "captcha after password" })
        }

        // The password form coming back means it was rejected. Terminal:
        // retrying spends the account's lockout budget for nothing.
        if (HAS_PASSWORD_FIELD.test(afterPasswordBody)) {
          return yield* new InvalidPassword({
            credentialId: credential.id,
            detail: feedbackFrom(afterPasswordBody)
          })
        }

        if (!HAS_OTP_FIELD.test(afterPasswordBody)) {
          return yield* new SsoUnavailable({
            detail: "unrecognized page after posting credentials"
          })
        }

        // 3. Answer the second factor.
        if (credential.totpSeed === undefined) {
          return yield* new InvalidTotp({
            credentialId: credential.id,
            detail: "SSO asked for a second factor but no TOTP seed is enrolled"
          })
        }

        const otpAction = FORM_ACTION.exec(afterPasswordBody)?.[1]
        if (otpAction === undefined) {
          return yield* new SsoUnavailable({ detail: "OTP form action not found" })
        }

        const code = yield* totp.generate(credential.totpSeed)

        const afterOtp = yield* client.execute(
          HttpClientRequest.post(unescapeHtml(otpAction)).pipe(
            HttpClientRequest.bodyUrlParams({ otp: code })
          )
        ).pipe(Effect.mapError(unavailable("SSO OTP post failed")))

        yield* assertUsable(afterOtp)

        const otpLocation = afterOtp.headers["location"]
        if (otpLocation === undefined) {
          const body = yield* bodyOf(afterOtp)
          // The OTP form coming back means the code was refused. Reported
          // separately from a bad password because the remedy differs.
          if (HAS_OTP_FIELD.test(body)) {
            return yield* new InvalidTotp({
              credentialId: credential.id,
              detail: feedbackFrom(body)
            })
          }
          return yield* new SsoUnavailable({ detail: "unrecognized page after OTP" })
        }

        const authCode = codeFrom(otpLocation)
        if (authCode === undefined) {
          return yield* new SsoUnavailable({
            detail: "SSO redirected without an authorization code after OTP"
          })
        }

        // 4. Exchange the code for tokens.
        return yield* exchange(client, {
          grant_type: "authorization_code",
          code: authCode,
          client_id: config.clientId,
          redirect_uri: config.redirectUri
        })
      })

      const refresh = Effect.fn("KeycloakSso.refresh")(
        function*(refreshToken: Redacted.Redacted<string>) {
          // Refresh is a single stateless call: no form, no cookies needed.
          return yield* exchange(baseClient, {
            grant_type: "refresh_token",
            refresh_token: Redacted.value(refreshToken),
            client_id: config.clientId
          })
        }
      )

      return SsoClient.of({ login, refresh })
    })
  )
}

/**
 * The HTTP client this adapter needs in production.
 *
 * `redirect: "manual"` is load-bearing, not a preference. `fetch` follows
 * redirects itself, beneath Effect's client, so with the default setting the
 * 302 carrying `#code=...` would be chased to the SPA and the authorization
 * code lost before any of our code ran. The fixture tests cannot catch this,
 * because a scripted client has no `fetch` underneath it to misbehave.
 */
export const layerHttp: Layer.Layer<HttpClient.HttpClient> = FetchHttpClient.layer.pipe(
  Layer.provide(Layer.succeed(FetchHttpClient.RequestInit, { redirect: "manual" }))
)
