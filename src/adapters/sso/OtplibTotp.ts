import { Effect, Layer, Redacted } from "effect"
import { generateSync } from "otplib"
import type { TotpSeed } from "../../domain/TotpSeed.ts"
import { TotpGenerator } from "../../ports/TotpGenerator.ts"

/** RFC 6238 default, and what Keycloak uses. */
export const TOTP_PERIOD_MILLIS = 30_000

/**
 * Below this much time left in the window, mint the *next* code instead.
 *
 * A code handed to the SSO with a second left can expire between our request
 * and Keycloak's validation, producing an `InvalidTotp` that looks exactly
 * like a wrong seed. Three seconds is PJePA's figure, arrived at against the
 * real SSO, and it costs at most three seconds on a small fraction of logins.
 */
const MIN_REMAINING_MILLIS = 3_000

/**
 * `TotpGenerator` over otplib.
 *
 * Time comes from Effect's `Clock`, never from `Date.now()`. That is what
 * makes window-rollover behaviour testable: under `TestClock` the whole
 * "wait for the next window" path runs in virtual time, so the suite proves
 * it without sleeping for real.
 */
export class OtplibTotp {
  static readonly layer: Layer.Layer<TotpGenerator> = Layer.effect(
    TotpGenerator,
    Effect.sync(() => {
      const generate = Effect.fn("OtplibTotp.generate")(function*(seed: TotpSeed) {
        const now = yield* Effect.clockWith((clock) => clock.currentTimeMillis)
        const remaining = TOTP_PERIOD_MILLIS - (now % TOTP_PERIOD_MILLIS)

        if (remaining < MIN_REMAINING_MILLIS) {
          yield* Effect.sleep(remaining)
        }

        // Re-read the clock: it has moved if we slept, and the code must
        // belong to the window we are actually in now.
        const at = yield* Effect.clockWith((clock) => clock.currentTimeMillis)

        return generateSync({
          secret: Redacted.value(seed),
          strategy: "totp",
          // otplib takes seconds; our clock is in milliseconds.
          epoch: Math.floor(at / 1000),
          period: TOTP_PERIOD_MILLIS / 1000
        })
      })

      return TotpGenerator.of({ generate })
    })
  )
}
