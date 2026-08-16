import { Effect } from "effect"

/**
 * SHA-256 of an API key, hex-encoded.
 *
 * Shared by the minting tool and the authentication path *deliberately*. If
 * these two ever computed the hash differently — a different digest, a
 * different encoding, a stray trim — keys would mint successfully and then
 * fail every request, with nothing in either component looking wrong. One
 * function makes that class of bug unrepresentable.
 *
 * A plain digest rather than a password KDF is the right choice here: an API
 * key is 256 bits of CSPRNG output, so there is no dictionary to defend
 * against, and a deliberately slow hash would add latency to every request for
 * no security gain.
 */
export const hashApiKey = (key: string): Effect.Effect<string> =>
  Effect.promise(async () => {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key))
    return Array.from(new Uint8Array(digest))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("")
  })
