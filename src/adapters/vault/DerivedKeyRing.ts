import { Context, Effect, Layer, Redacted } from "effect"
import type { TenantId } from "../../domain/Model.ts"
import { KeyRing, KeyUnavailable } from "../../ports/KeyRing.ts"

/**
 * Per-tenant data keys derived from one master key with HKDF-SHA256.
 *
 * The alternative — generating a random DEK per tenant and storing it wrapped
 * by the KEK — needs a second table and a second failure mode. Deriving
 * instead means there is no DEK at rest anywhere: the only stored secret is
 * the master key, which lives in Cloudflare SecretsStore (or KMS) and is
 * write-only there.
 *
 * The trade-off is honest and worth stating: rotating the master key
 * re-derives every tenant key, so rotation requires re-encrypting the vault
 * rather than just re-wrapping a DEK. `INFO_VERSION` exists so a future
 * scheme can be introduced alongside the current one during such a migration.
 */

/** Bumped only when the derivation scheme itself changes. */
const INFO_VERSION = "pdpj-broker-dek-v1"

/**
 * A master key shorter than this is almost certainly a placeholder that
 * escaped into a real environment. Failing loudly beats silently protecting
 * a vault with a guessable key.
 */
const MIN_KEK_LENGTH = 32

/**
 * Fixed, non-secret salt. HKDF's security rests on the master key's entropy;
 * the salt only separates this derivation from any other use of the same key,
 * and per-tenant separation is carried in `info` instead.
 */
const SALT = new TextEncoder().encode("pdpj-token-broker")

/**
 * The master key. A `Redacted` string rather than raw bytes because that is
 * what a secrets store hands back, and `Redacted` keeps it out of logs and
 * traces on the way through.
 */
export class Kek extends Context.Service<Kek, Redacted.Redacted<string>>()(
  "broker/adapters/DerivedKeyRing/Kek"
) {}

export class DerivedKeyRing {
  static readonly layer: Layer.Layer<KeyRing, never, Kek> = Layer.effect(
    KeyRing,
    Effect.gen(function*() {
      const kek = yield* Kek

      /**
       * Imported once per instance. The result is a WebCrypto handle, not key
       * material, so caching it keeps no secret in reachable memory.
       */
      const masterKey = Effect.suspend(() => {
        const raw = Redacted.value(kek)
        if (raw.length < MIN_KEK_LENGTH) {
          return Effect.fail(
            new KeyUnavailable({
              tenantId: "*",
              detail: `master key must be at least ${MIN_KEK_LENGTH} characters`
            })
          )
        }
        return Effect.tryPromise({
          try: () =>
            crypto.subtle.importKey(
              "raw",
              new TextEncoder().encode(raw) as BufferSource,
              "HKDF",
              // Never extractable: the master key must not be readable back
              // out of the runtime once imported.
              false,
              ["deriveKey"]
            ),
          catch: () =>
            new KeyUnavailable({ tenantId: "*", detail: "master key could not be imported" })
        })
      }).pipe(Effect.cached)

      const cachedMaster = yield* masterKey

      const dekFor = Effect.fn("DerivedKeyRing.dekFor")(function*(tenantId: TenantId) {
        const master = yield* cachedMaster

        return yield* Effect.tryPromise({
          try: () =>
            crypto.subtle.deriveKey(
              {
                name: "HKDF",
                hash: "SHA-256",
                salt: SALT as BufferSource,
                // The tenant id is the context separator: two tenants derive
                // unrelated keys from the same master, so one compromised key
                // cannot open another tenant's rows.
                info: new TextEncoder().encode(`${INFO_VERSION}:${tenantId}`) as BufferSource
              },
              master,
              { name: "AES-GCM", length: 256 },
              // Non-extractable, so the derived key cannot be exported,
              // serialized, or logged even by our own code.
              false,
              ["encrypt", "decrypt"]
            ),
          catch: () => new KeyUnavailable({ tenantId, detail: "key derivation failed" })
        })
      })

      return KeyRing.of({ dekFor })
    })
  )
}
