import { assert, describe, it } from "@effect/vitest"
import { Effect, Schema } from "effect"
import { Cpf } from "../../src/domain/Cpf.ts"

/**
 * A CPF is the tenant's identity at the SSO. Getting it wrong means a login
 * attempt against a nonexistent account, which counts toward the SSO's
 * lockout budget — so it is validated at the edge of the system, never
 * deeper in.
 */
describe("Cpf", () => {
  const decode = Schema.decodeUnknownEffect(Cpf)

  // Real, structurally valid CPFs (check digits computed correctly).
  const valid = ["12345678909", "52998224725", "11144477735"]

  it.effect.each(valid)("accepts a valid CPF: %s", (raw) =>
    Effect.gen(function*() {
      const cpf = yield* decode(raw)
      assert.strictEqual(cpf, raw)
    }))

  it.effect("strips punctuation from a formatted CPF", () =>
    Effect.gen(function*() {
      const cpf = yield* decode("529.982.247-25")
      assert.strictEqual(cpf, "52998224725")
    }))

  it.effect("rejects a CPF whose check digits are wrong", () =>
    Effect.gen(function*() {
      const result = yield* Effect.result(decode("52998224726"))
      assert.isTrue(result._tag === "Failure")
    }))

  it.effect("rejects repeated-digit CPFs, which pass the raw checksum", () =>
    Effect.gen(function*() {
      const result = yield* Effect.result(decode("11111111111"))
      assert.isTrue(result._tag === "Failure")
    }))

  it.effect.each(["1234567890", "123456789012", "", "abcdefghijk"])(
    "rejects a malformed CPF: %s",
    (raw) =>
      Effect.gen(function*() {
        const result = yield* Effect.result(decode(raw))
        assert.isTrue(result._tag === "Failure")
      })
  )

  it.effect("never appears in an error message, since it is personal data", () =>
    Effect.gen(function*() {
      const result = yield* Effect.result(decode("52998224726"))
      assert.isTrue(result._tag === "Failure")
      if (result._tag === "Failure") {
        assert.isFalse(JSON.stringify(result.failure).includes("52998224726"))
      }
    }))
})
