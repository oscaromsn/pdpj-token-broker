import { Context, type Effect, type Option, type Redacted, Schema } from "effect"
import type { CredentialId, TenantId } from "../domain/Model.ts"

export class SessionUnavailable extends Schema.TaggedError<SessionUnavailable>()(
  "SessionUnavailable",
  { detail: Schema.String, cause: Schema.optional(Schema.Defect()) }
) {}

/**
 * Port: the durable home of a gov.br session's refresh token.
 *
 * Separate from `TokenCache` on purpose. The cache holds the short-lived
 * access token and may be cleared at will; this holds the *refresh* token,
 * which is the thing that actually keeps a gov.br account usable without
 * re-login and must survive a cold start.
 *
 * It is also separate from `CredentialVault`, which stores passwords and TOTP
 * seeds. A gov.br account has neither — it has a rotating refresh token — so
 * conflating the two would force one storage shape to carry both kinds of
 * secret. Keeping them apart lets a deployment use password credentials,
 * session credentials, or both, without the storage of one knowing about the
 * other.
 *
 * The refresh token rotates on every use (Keycloak issues a new one and
 * invalidates the old), so `put` is called after every successful refresh —
 * losing that write means the next cold start authenticates with a token the
 * SSO has already retired.
 */
export class SessionStore extends Context.Service<SessionStore, {
  get(
    tenantId: TenantId,
    id: CredentialId
  ): Effect.Effect<Option.Option<Redacted.Redacted<string>>, SessionUnavailable>

  put(
    tenantId: TenantId,
    id: CredentialId,
    refreshToken: Redacted.Redacted<string>
  ): Effect.Effect<void, SessionUnavailable>

  /** Drop a session the SSO has finally rejected, so the state is honest. */
  clear(tenantId: TenantId, id: CredentialId): Effect.Effect<void, SessionUnavailable>
}>()("broker/ports/SessionStore") {}
