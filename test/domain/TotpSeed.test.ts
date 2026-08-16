import { assert, describe, it } from "@effect/vitest"
import { Effect, Redacted, Schema } from "effect"
import { TotpSeed } from "../../src/domain/TotpSeed.ts"

/**
 * The seed is the highest-value secret the broker holds: combined with the
 * password it grants unattended, factor-complete access. It is a Redacted
 * value from the moment it is parsed so that it cannot be logged by accident.
 */
describe("TotpSeed", () => {
  const decode = Schema.decodeUnknownEffect(TotpSeed)

  it.effect("accepts a base32 seed", () =>
    Effect.gen(function*() {
      const seed = yield* decode("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
      assert.strictEqual(Redacted.value(seed), "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
    }))

  it.effect("normalizes spacing and case, as authenticator apps display it", () =>
    Effect.gen(function*() {
      const seed = yield* decode("jbsw y3dp ehpk 3pxp jbsw y3dp ehpk 3pxp")
      assert.strictEqual(Redacted.value(seed), "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
    }))

  it.effect("rejects characters outside the base32 alphabet", () =>
    Effect.gen(function*() {
      // 0, 1 and 8 are not in RFC 4648 base32.
      const result = yield* Effect.result(decode("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PX0"))
      assert.isTrue(result._tag === "Failure")
    }))

  it.effect("rejects a seed that is too short to be meaningful", () =>
    Effect.gen(function*() {
      const result = yield* Effect.result(decode("JBSW"))
      assert.isTrue(result._tag === "Failure")
    }))

  it.effect("rejects a seed below the 128-bit floor the generator enforces", () =>
    Effect.gen(function*() {
      // 16 base32 chars = 80 bits. Accepting it here would store a seed that
      // every future login attempt would fail to use.
      const result = yield* Effect.result(decode("JBSWY3DPEHPK3PXP"))
      assert.isTrue(result._tag === "Failure")
    }))

  it.effect("does not expose the seed when stringified", () =>
    Effect.gen(function*() {
      const seed = yield* decode("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
      assert.isFalse(String(seed).includes("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"))
      assert.isFalse(JSON.stringify(seed).includes("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"))
    }))
})
