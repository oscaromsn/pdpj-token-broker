import { Schema } from "effect"
import * as SchemaGetter from "effect/SchemaGetter"

/** RFC 4648 base32 alphabet: A–Z and 2–7, with optional `=` padding. */
const BASE32 = /^[A-Z2-7]+=*$/

/**
 * 26 base32 characters is 128 bits, the floor RFC 4226 recommends and the
 * minimum the code generator will actually accept.
 *
 * The number is set by the generator, not by taste: a shorter seed would pass
 * validation here, be encrypted, be stored, and then fail every login — a
 * failure at 3am instead of at enrollment, when the user is still present to
 * fix it. Keycloak issues 20-byte (32-character) secrets, so real PDPJ seeds
 * clear this comfortably.
 */
const MIN_LENGTH = 26

/**
 * A TOTP shared secret in base32, held as a `Redacted` value.
 *
 * Users copy this out of the authenticator's QR-code screen, where it is shown
 * in lowercase and split into readable groups — so whitespace is stripped and
 * the value is upper-cased before validation.
 *
 * Wrapping in `Redacted` is the point: it makes the seed unprintable through
 * `String`, `JSON.stringify`, and Effect's own log/span formatting, so the one
 * secret that would make a leak factor-complete cannot escape through a log
 * line.
 */
export const TotpSeed = Schema.RedactedFromValue(
  Schema.String.pipe(
    Schema.decodeTo(Schema.String, {
      decode: SchemaGetter.transform((raw: string) => raw.replace(/\s/g, "").toUpperCase()),
      encode: SchemaGetter.passthrough()
    }),
    Schema.check(
      Schema.makeFilter((seed: string) =>
        seed.length >= MIN_LENGTH && BASE32.test(seed)
          ? undefined
          : `must be at least ${MIN_LENGTH} base32 characters`
      )
    )
  ),
  // Encoding is what would write the seed back out as plaintext. Forbidding it
  // means an accidental `Schema.encode` on a stored credential fails loudly
  // instead of quietly serializing the secret.
  { label: "TotpSeed", disallowEncode: true }
)

export type TotpSeed = typeof TotpSeed.Type
