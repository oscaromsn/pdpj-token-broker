import { Effect, Schema } from "effect"

/**
 * AES-256-GCM sealing, on WebCrypto so the same code runs in a Worker and in
 * Node without a polyfill.
 *
 * GCM appends its 16-byte authentication tag to the ciphertext, so — unlike
 * the Node `createCipheriv` style used in jurify — there is no separate `tag`
 * field to carry. One less value to store is one less value to lose.
 */

const ALGORITHM = "AES-GCM"
const KEY_BITS = 256

/**
 * 96 bits, the size GCM is specified for. Longer nonces are re-hashed
 * internally and gain nothing; shorter ones raise collision risk.
 */
const IV_BYTES = 12

/**
 * Base64 text, validated as such.
 *
 * Worth checking rather than trusting: a malformed field read back from
 * storage should fail as bad data at the edge, not as an opaque decode
 * throw from deep inside `open`.
 */
const Base64 = Schema.String.check(Schema.isBase64())

/** Sealed bytes plus the nonce needed to open them. Safe to store as-is. */
export class Sealed extends Schema.Class<Sealed>("broker/crypto/Sealed")({
  /** base64 of ciphertext ‖ GCM tag */
  ciphertext: Base64,
  /** base64 of the 96-bit nonce */
  iv: Base64
}) {}

/**
 * Bytes ⇄ base64 via Schema rather than hand-rolled `atob`/`btoa` loops:
 * one implementation, already correct, and it validates on the way in.
 */
const bytesToBase64 = Schema.encodeSync(Schema.Uint8ArrayFromBase64)
const bytesFromBase64 = Schema.decodeSync(Schema.Uint8ArrayFromBase64)

export class SealFailed extends Schema.TaggedError<SealFailed>()("SealFailed", {
  cause: Schema.Defect()
}) {}

/**
 * Opening failed. In GCM this is indistinguishable between "wrong key" and
 * "modified ciphertext" — by design — so the error deliberately does not
 * speculate about which.
 */
export class OpenFailed extends Schema.TaggedError<OpenFailed>()("OpenFailed", {
  cause: Schema.Defect()
}) {}

const generateKey: Effect.Effect<CryptoKey, SealFailed> = Effect.tryPromise({
  try: () => crypto.subtle.generateKey({ name: ALGORITHM, length: KEY_BITS }, true, ["encrypt", "decrypt"]),
  catch: (cause) => new SealFailed({ cause })
})

const exportKey = Effect.fn("Envelope.exportKey")(function*(key: CryptoKey) {
  const raw = yield* Effect.tryPromise({
    try: () => crypto.subtle.exportKey("raw", key),
    catch: (cause) => new SealFailed({ cause })
  })
  return new Uint8Array(raw)
})

const importKey = Effect.fn("Envelope.importKey")(function*(raw: Uint8Array) {
  return yield* Effect.tryPromise({
    try: () =>
      crypto.subtle.importKey("raw", raw as BufferSource, { name: ALGORITHM }, true, [
        "encrypt",
        "decrypt"
      ]),
    catch: (cause) => new SealFailed({ cause })
  })
})

const seal = Effect.fn("Envelope.seal")(function*(key: CryptoKey, plaintext: string) {
  // Nonces come from the CSPRNG directly, never from Effect's `Random`:
  // `Random` is seedable and deterministic under test, and a repeated GCM
  // nonce would break confidentiality outright. Determinism is exactly what
  // must not happen here.
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES))
  const encoded = new TextEncoder().encode(plaintext)

  const buffer = yield* Effect.tryPromise({
    try: () => crypto.subtle.encrypt({ name: ALGORITHM, iv }, key, encoded as BufferSource),
    catch: (cause) => new SealFailed({ cause })
  })

  return new Sealed({
    ciphertext: bytesToBase64(new Uint8Array(buffer)),
    iv: bytesToBase64(iv)
  })
})

const open = Effect.fn("Envelope.open")(function*(key: CryptoKey, sealed: Sealed) {
  const buffer = yield* Effect.tryPromise({
    // `decrypt` throws when the tag does not verify, which is the check that
    // makes tampering detectable rather than silently decoded as garbage.
    try: () =>
      crypto.subtle.decrypt(
        { name: ALGORITHM, iv: bytesFromBase64(sealed.iv) as BufferSource },
        key,
        bytesFromBase64(sealed.ciphertext) as BufferSource
      ),
    catch: (cause) => new OpenFailed({ cause })
  })

  return new TextDecoder().decode(buffer)
})

export const Envelope = {
  generateKey,
  exportKey,
  importKey,
  seal,
  open
} as const
