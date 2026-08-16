import { Context, type Effect, Schema } from "effect"
import type { TenantId } from "../domain/Model.ts"

export class KeyUnavailable extends Schema.TaggedError<KeyUnavailable>()(
  "KeyUnavailable",
  { tenantId: Schema.String, detail: Schema.String }
) {}

/**
 * Port: supplies the per-tenant data key (DEK) used to seal credentials.
 *
 * This is the envelope boundary. The key-encryption key never appears in this
 * interface at all — it lives in KMS or Cloudflare SecretsStore, and the
 * adapter's whole job is to unwrap a DEK with it. Because the port hands back
 * an opaque `CryptoKey` rather than key material, callers cannot accidentally
 * log, serialize, or persist the key they are handed.
 *
 * Keys are per tenant so that a compromise or a rotation is scoped to one
 * tenant instead of the whole vault.
 */
export class KeyRing extends Context.Service<KeyRing, {
  dekFor(tenantId: TenantId): Effect.Effect<CryptoKey, KeyUnavailable>
}>()("broker/ports/KeyRing") {}
