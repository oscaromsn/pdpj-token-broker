import { assert, describe, it } from "@effect/vitest"
import { Effect, Fiber, Schema } from "effect"
import { TestClock } from "effect/testing"
import { verifySync } from "otplib"
import { OtplibTotp, TOTP_PERIOD_MILLIS } from "../../src/adapters/sso/OtplibTotp.ts"
import { TotpSeed } from "../../src/domain/TotpSeed.ts"
import { TotpGenerator } from "../../src/ports/TotpGenerator.ts"

const SEED_TEXT = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
const seed = Schema.decodeUnknownSync(TotpSeed)(SEED_TEXT)

const generate = Effect.gen(function*() {
  const totp = yield* TotpGenerator
  return yield* totp.generate(seed)
}).pipe(Effect.provide(OtplibTotp.layer))

describe("OtplibTotp", () => {
  it.effect("produces a six-digit code the algorithm itself accepts", () =>
    Effect.gen(function*() {
      // Start mid-window so no wait is triggered.
      yield* TestClock.adjust(5_000)
      const code = yield* generate

      assert.match(code, /^\d{6}$/)
      // Verified against otplib's own checker at the same instant, so this
      // asserts real TOTP correctness rather than "six digits came back".
      const now = yield* Effect.clockWith((c) => c.currentTimeMillis)
      const { valid } = verifySync({
        secret: SEED_TEXT,
        strategy: "totp",
        token: code,
        epoch: Math.floor(now / 1000)
      })
      assert.isTrue(valid)
    }))

  it.effect("returns the same code twice within one window", () =>
    Effect.gen(function*() {
      yield* TestClock.adjust(1_000)
      const first = yield* generate
      yield* TestClock.adjust(2_000)
      const second = yield* generate
      assert.strictEqual(first, second)
    }))

  it.effect("returns a different code in the next window", () =>
    Effect.gen(function*() {
      yield* TestClock.adjust(1_000)
      const first = yield* generate
      yield* TestClock.adjust(TOTP_PERIOD_MILLIS)
      const second = yield* generate
      assert.notStrictEqual(first, second)
    }))

  it.effect("waits for the next window when the current one is about to expire", () =>
    Effect.gen(function*() {
      // 1s left in the window: a code minted now can expire in flight and be
      // rejected by the SSO. PJePA learned this the hard way; the generator
      // must sleep into the next window instead.
      yield* TestClock.adjust(TOTP_PERIOD_MILLIS - 1_000)

      const fiber = yield* Effect.forkChild(generate)

      // Nothing should be produced yet — the generator is sleeping.
      yield* TestClock.adjust(500)
      assert.strictEqual(fiber.pollUnsafe(), undefined)

      // Cross into the next window; now it may proceed.
      yield* TestClock.adjust(1_000)
      const code = yield* Fiber.join(fiber)
      assert.match(code, /^\d{6}$/)

      // And the code belongs to the *new* window, not the expiring one.
      const now = yield* Effect.clockWith((c) => c.currentTimeMillis)
      const { valid } = verifySync({
        secret: SEED_TEXT,
        strategy: "totp",
        token: code,
        epoch: Math.floor(now / 1000)
      })
      assert.isTrue(valid)
    }))

  it.effect("does not wait when the window has plenty of time left", () =>
    Effect.gen(function*() {
      yield* TestClock.adjust(1_000)
      // No clock advance is needed for this to complete, which is the
      // assertion: a fresh window must not introduce latency on every login.
      const code = yield* generate
      assert.match(code, /^\d{6}$/)
    }))
})
