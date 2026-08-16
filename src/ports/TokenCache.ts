import { Context, type Effect, type Option } from "effect"
import type { CredentialId, TenantId, TokenSet } from "../domain/Model.ts"

/**
 * Port: short-lived storage for minted tokens.
 *
 * Deliberately dumb — get, set, invalidate. Freshness policy lives in the
 * broker, not here, so that swapping KV for Redis cannot silently change when
 * a token is considered expired.
 *
 * Implementations must treat a miss as a normal outcome (`Option.none`), not
 * an error: a cold cache is the expected state, not a failure.
 */
export class TokenCache extends Context.Service<TokenCache, {
  get(tenantId: TenantId, id: CredentialId): Effect.Effect<Option.Option<TokenSet>>
  set(tenantId: TenantId, id: CredentialId, tokens: TokenSet): Effect.Effect<void>
  /** Drop a token the SSO has rejected, so the next call re-mints. */
  invalidate(tenantId: TenantId, id: CredentialId): Effect.Effect<void>
}>()("broker/ports/TokenCache") {}
