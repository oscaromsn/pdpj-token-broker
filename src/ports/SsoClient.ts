import { Context, type Effect, type Redacted } from "effect"
import type {
  ChallengeRequired,
  InvalidPassword,
  InvalidTotp,
  SsoUnavailable
} from "../domain/Errors.ts"
import type { Credential, TokenSet } from "../domain/Model.ts"

/**
 * Port: the PDPJ Keycloak SSO.
 *
 * Two operations, because they have genuinely different costs and failure
 * modes. `refresh` is cheap and — crucially — does not re-trigger 2FA, which
 * is what lets a tenant pay the second-factor cost once and coast. `login` is
 * expensive and is the only path that can fail on a bad password or seed.
 *
 * The error channel is the contract that makes the broker's cooldown logic
 * possible: `InvalidPassword` and `InvalidTotp` are terminal (retrying locks
 * the account), `SsoUnavailable` is transient, and `ChallengeRequired` means
 * "this transport cannot proceed — escalate", not "failed".
 */
export class SsoClient extends Context.Service<SsoClient, {
  login(
    credential: Credential
  ): Effect.Effect<
    TokenSet,
    InvalidPassword | InvalidTotp | ChallengeRequired | SsoUnavailable,
    never
  >

  refresh(
    refreshToken: Redacted.Redacted<string>
  ): Effect.Effect<TokenSet, SsoUnavailable>
}>()("broker/ports/SsoClient") {}

/**
 * Port: the browser-driven fallback, used only when the HTTP transport hits a
 * challenge it cannot answer.
 *
 * Same `login` shape as `SsoClient` minus `ChallengeRequired` — a real browser
 * either clears the challenge or fails outright, so there is nothing further
 * to escalate to. Keeping it a separate port (rather than a flag on
 * `SsoClient`) is what lets the Worker deploy without a browser at all and
 * hand this to a container later, with no change to the domain.
 */
export class BrowserLogin extends Context.Service<BrowserLogin, {
  login(
    credential: Credential
  ): Effect.Effect<TokenSet, InvalidPassword | InvalidTotp | SsoUnavailable>
}>()("broker/ports/BrowserLogin") {}
