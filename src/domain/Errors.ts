import { Schema } from "effect"

/**
 * Every failure the broker can produce, as tagged errors.
 *
 * These are deliberately distinct rather than one `LoginFailed`: the whole
 * point of the design is that an operator can tell "your password changed"
 * apart from "your seed is wrong" apart from "we are in cooldown", because
 * each demands a different action. Collapsing them would make the service
 * unoperable exactly when it matters.
 */

/** The stored credential does not exist, or belongs to another tenant. */
export class CredentialNotFound extends Schema.TaggedError<CredentialNotFound>()(
  "CredentialNotFound",
  { credentialId: Schema.String }
) {}

/**
 * The SSO rejected the password. Terminal until a human re-enrolls — retrying
 * is what gets the account locked, so this must never be retryable.
 */
export class InvalidPassword extends Schema.TaggedError<InvalidPassword>()(
  "InvalidPassword",
  { credentialId: Schema.String, detail: Schema.String }
) {}

/**
 * The SSO accepted the password but rejected the second factor. Distinct from
 * `InvalidPassword` because the fix is different: re-capture the seed, or
 * check for clock drift, rather than reset the password.
 */
export class InvalidTotp extends Schema.TaggedError<InvalidTotp>()(
  "InvalidTotp",
  { credentialId: Schema.String, detail: Schema.String }
) {}

/**
 * Too many consecutive login failures; the breaker is open. Carries the
 * remaining cooldown so callers can report "try again in N seconds" instead
 * of hammering.
 */
export class CircuitOpen extends Schema.TaggedError<CircuitOpen>()(
  "CircuitOpen",
  { credentialId: Schema.String, retryAfterMillis: Schema.Number }
) {}

/**
 * The login page presented a challenge the HTTP path cannot answer (captcha,
 * JS wall). Signals the broker to escalate to the browser adapter — and, when
 * that is unavailable, tells operators that CNJ changed the login flow.
 */
export class ChallengeRequired extends Schema.TaggedError<ChallengeRequired>()(
  "ChallengeRequired",
  { detail: Schema.String }
) {}

/** The SSO was unreachable or returned an unusable response. Retryable. */
export class SsoUnavailable extends Schema.TaggedError<SsoUnavailable>()(
  "SsoUnavailable",
  { detail: Schema.String, cause: Schema.optional(Schema.Defect()) }
) {}

/** Decryption failed: wrong key, or the ciphertext was tampered with. */
export class VaultCorrupt extends Schema.TaggedError<VaultCorrupt>()(
  "VaultCorrupt",
  { credentialId: Schema.String, detail: Schema.String }
) {}

/** The vault's storage or key service failed. Retryable. */
export class VaultUnavailable extends Schema.TaggedError<VaultUnavailable>()(
  "VaultUnavailable",
  { detail: Schema.String, cause: Schema.optional(Schema.Defect()) }
) {}
