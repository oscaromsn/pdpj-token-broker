import { assert, describe, it } from "@effect/vitest"
import { Effect, Layer, Redacted, Schema } from "effect"
import { DerivedKeyRing, Kek } from "../../src/adapters/vault/DerivedKeyRing.ts"
import { Envelope } from "../../src/crypto/Envelope.ts"
import { TenantId } from "../../src/domain/Model.ts"
import { KeyRing } from "../../src/ports/KeyRing.ts"

const tenantA = Schema.decodeUnknownSync(TenantId)("tenant-a")
const tenantB = Schema.decodeUnknownSync(TenantId)("tenant-b")

const KEK = "a-master-key-of-sufficient-length-for-hkdf"

const ringWith = (kek: string) =>
  DerivedKeyRing.layer.pipe(
    Layer.provide(Layer.succeed(Kek, Redacted.make(kek)))
  )

describe("DerivedKeyRing", () => {
  it.effect("derives the same key for a tenant every time", () =>
    Effect.gen(function*() {
      // Determinism is a correctness requirement, not a nicety: a redeploy
      // must still be able to open yesterday's ciphertext.
      const sealed = yield* Effect.gen(function*() {
        const ring = yield* KeyRing
        return yield* Envelope.seal(yield* ring.dekFor(tenantA), "secret")
      }).pipe(Effect.provide(ringWith(KEK)))

      const opened = yield* Effect.gen(function*() {
        const ring = yield* KeyRing
        return yield* Envelope.open(yield* ring.dekFor(tenantA), sealed)
      }).pipe(Effect.provide(ringWith(KEK)))

      assert.strictEqual(opened, "secret")
    }))

  it.effect("derives a different key per tenant, so one key opens one tenant", () =>
    Effect.gen(function*() {
      const result = yield* Effect.gen(function*() {
        const ring = yield* KeyRing
        const sealed = yield* Envelope.seal(yield* ring.dekFor(tenantA), "secret")
        return yield* Effect.result(Envelope.open(yield* ring.dekFor(tenantB), sealed))
      }).pipe(Effect.provide(ringWith(KEK)))

      assert.isTrue(result._tag === "Failure")
    }))

  it.effect("derives different keys under a different master key", () =>
    Effect.gen(function*() {
      const sealed = yield* Effect.gen(function*() {
        const ring = yield* KeyRing
        return yield* Envelope.seal(yield* ring.dekFor(tenantA), "secret")
      }).pipe(Effect.provide(ringWith(KEK)))

      const result = yield* Effect.gen(function*() {
        const ring = yield* KeyRing
        return yield* Effect.result(Envelope.open(yield* ring.dekFor(tenantA), sealed))
      }).pipe(Effect.provide(ringWith("a-completely-different-master-key-value")))

      // Rotating the master key must invalidate old ciphertext rather than
      // silently producing garbage.
      assert.isTrue(result._tag === "Failure")
    }))

  it.effect("produces non-extractable keys, so a DEK can never be logged", () =>
    Effect.gen(function*() {
      const result = yield* Effect.gen(function*() {
        const ring = yield* KeyRing
        const key = yield* ring.dekFor(tenantA)
        assert.isFalse(key.extractable)
        // Exporting must fail at the WebCrypto layer, not merely by convention.
        return yield* Effect.result(Envelope.exportKey(key))
      }).pipe(Effect.provide(ringWith(KEK)))

      assert.isTrue(result._tag === "Failure")
    }))

  it.effect("rejects a master key too short to be a real secret", () =>
    Effect.gen(function*() {
      const result = yield* Effect.gen(function*() {
        const ring = yield* KeyRing
        return yield* Effect.result(ring.dekFor(tenantA))
      }).pipe(Effect.provide(ringWith("short")))

      assert.isTrue(result._tag === "Failure")
      if (result._tag === "Failure") {
        assert.strictEqual(result.failure._tag, "KeyUnavailable")
      }
    }))
})
