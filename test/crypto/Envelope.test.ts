import { assert, describe, it } from "@effect/vitest"
import { Effect } from "effect"
import { Envelope, Sealed } from "../../src/crypto/Envelope.ts"

/**
 * These tests are the reason the vault can be trusted. AES-GCM is only safe
 * under two conditions — a never-repeated nonce, and an authentication tag
 * that is actually checked — and both are properties of *our* usage, not of
 * the algorithm. So both are asserted here rather than assumed.
 */
describe("Envelope", () => {
  const secret = "correct-horse-battery-staple"

  it.effect("round-trips a value through seal and open", () =>
    Effect.gen(function*() {
      const key = yield* Envelope.generateKey
      const sealed = yield* Envelope.seal(key, secret)
      const opened = yield* Envelope.open(key, sealed)
      assert.strictEqual(opened, secret)
    }))

  it.effect("stores nothing resembling the plaintext", () =>
    Effect.gen(function*() {
      const key = yield* Envelope.generateKey
      const sealed = yield* Envelope.seal(key, secret)
      assert.isFalse(sealed.ciphertext.includes(secret))
      assert.isFalse(JSON.stringify(sealed).includes(secret))
    }))

  it.effect("never reuses a nonce, even for identical plaintext", () =>
    Effect.gen(function*() {
      const key = yield* Envelope.generateKey
      // Nonce reuse under GCM leaks the XOR of the plaintexts and destroys
      // the authentication guarantee. Sealing the same value twice must
      // therefore produce different IVs and different ciphertexts.
      const a = yield* Envelope.seal(key, secret)
      const b = yield* Envelope.seal(key, secret)
      assert.notStrictEqual(a.iv, b.iv)
      assert.notStrictEqual(a.ciphertext, b.ciphertext)
    }))

  /**
   * Flip exactly one bit of a base64 payload, keeping it valid base64.
   *
   * Mangling the base64 text itself would make `atob` throw, and the test
   * would pass without ever exercising the authentication tag — proving
   * nothing about GCM. Decoding, flipping a bit, and re-encoding keeps the
   * input well-formed so the only thing that can reject it is the tag.
   */
  const flipBit = (encoded: string, index: number): string => {
    const binary = atob(encoded)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
    bytes[index] = bytes[index]! ^ 0x01
    let out = ""
    for (const byte of bytes) out += String.fromCharCode(byte)
    return btoa(out)
  }

  it.effect("rejects a ciphertext with a single flipped bit", () =>
    Effect.gen(function*() {
      const key = yield* Envelope.generateKey
      const sealed = yield* Envelope.seal(key, secret)
      const tampered = new Sealed({
        ...sealed,
        ciphertext: flipBit(sealed.ciphertext, 0)
      })

      const result = yield* Effect.result(Envelope.open(key, tampered))
      assert.isTrue(result._tag === "Failure")
      if (result._tag === "Failure") {
        // Rejected by the tag check, not by malformed input.
        assert.strictEqual(result.failure._tag, "OpenFailed")
      }
    }))

  it.effect("rejects a flipped bit in the authentication tag itself", () =>
    Effect.gen(function*() {
      const key = yield* Envelope.generateKey
      const sealed = yield* Envelope.seal(key, secret)
      const raw = atob(sealed.ciphertext)
      const tampered = new Sealed({
        ...sealed,
        // Last 16 bytes are the GCM tag.
        ciphertext: flipBit(sealed.ciphertext, raw.length - 1)
      })

      const result = yield* Effect.result(Envelope.open(key, tampered))
      assert.isTrue(result._tag === "Failure")
    }))

  it.effect("rejects a tampered nonce", () =>
    Effect.gen(function*() {
      const key = yield* Envelope.generateKey
      const sealed = yield* Envelope.seal(key, secret)
      const tampered = new Sealed({ ...sealed, iv: flipBit(sealed.iv, 0) })

      const result = yield* Effect.result(Envelope.open(key, tampered))
      assert.isTrue(result._tag === "Failure")
      if (result._tag === "Failure") {
        assert.strictEqual(result.failure._tag, "OpenFailed")
      }
    }))

  it.effect("cannot be opened with a different key", () =>
    Effect.gen(function*() {
      const key = yield* Envelope.generateKey
      const other = yield* Envelope.generateKey
      const sealed = yield* Envelope.seal(key, secret)

      const result = yield* Effect.result(Envelope.open(other, sealed))
      assert.isTrue(result._tag === "Failure")
    }))

  it.effect("round-trips a key through export and import, so DEKs can be wrapped", () =>
    Effect.gen(function*() {
      const key = yield* Envelope.generateKey
      const raw = yield* Envelope.exportKey(key)
      const reimported = yield* Envelope.importKey(raw)

      const sealed = yield* Envelope.seal(key, secret)
      const opened = yield* Envelope.open(reimported, sealed)
      assert.strictEqual(opened, secret)
    }))

  it.effect("preserves non-ASCII, since Brazilian names and errors carry accents", () =>
    Effect.gen(function*() {
      const key = yield* Envelope.generateKey
      const accented = "Usuário ou senha inválido — ação"
      const sealed = yield* Envelope.seal(key, accented)
      assert.strictEqual(yield* Envelope.open(key, sealed), accented)
    }))
})
