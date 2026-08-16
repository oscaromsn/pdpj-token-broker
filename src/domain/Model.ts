import { Schema } from "effect"
import { Cpf } from "./Cpf.ts"
import { TotpSeed } from "./TotpSeed.ts"

/** Opaque handle a caller uses to name a credential without holding it. */
export const CredentialId = Schema.String.pipe(
  Schema.check(Schema.isMinLength(1)),
  Schema.brand("CredentialId")
)
export type CredentialId = typeof CredentialId.Type

/** Tenant boundary. Every vault read is scoped by this. */
export const TenantId = Schema.String.pipe(
  Schema.check(Schema.isMinLength(1)),
  Schema.brand("TenantId")
)
export type TenantId = typeof TenantId.Type

/**
 * Lifecycle of a stored credential, mirroring jurify's cofre.
 *
 * A credential is only `active` once a real login has proven it works — we
 * never trust an untested credential — and it visibly rots to `error` or
 * `expired` so operators re-enroll instead of watching silent failures.
 */
export const CredentialStatus = Schema.Literals([
  "validating",
  "active",
  "error",
  "expired",
  "removed"
])
export type CredentialStatus = typeof CredentialStatus.Type

/**
 * The decrypted secrets. Constructed only inside the vault adapter, held only
 * for the duration of a login, and never returned across the API boundary.
 */
export class Credential extends Schema.Class<Credential>("broker/domain/Credential")({
  id: CredentialId,
  tenantId: TenantId,
  cpf: Cpf,
  password: Schema.RedactedFromValue(Schema.String, { disallowEncode: true }),
  // Absent when the account has no second factor enrolled. The login engine
  // branches on this rather than assuming 2FA is always present.
  totpSeed: Schema.optional(TotpSeed)
}) {}

/**
 * What the API is allowed to say about a credential: enough to operate it,
 * nothing that helps use it. There is no field here that could carry a
 * password or seed — the type makes leaking one impossible, not merely
 * discouraged.
 */
export class CredentialView extends Schema.Class<CredentialView>("broker/domain/CredentialView")({
  id: CredentialId,
  tenantId: TenantId,
  label: Schema.String,
  /** e.g. "062******56" — enough to recognize, not enough to impersonate. */
  cpfMasked: Schema.String,
  hasTotp: Schema.Boolean,
  status: CredentialStatus,
  lastLoginAt: Schema.optional(Schema.Number),
  lastError: Schema.optional(Schema.String)
}) {}

/**
 * A minted access token plus the refresh token that renews it.
 *
 * `expiresAt` is absolute epoch millis rather than the `expires_in` the SSO
 * returns: a duration is only meaningful next to the instant it was issued,
 * and storing the duration invites treating a cached token as fresher than
 * it is.
 */
export class TokenSet extends Schema.Class<TokenSet>("broker/domain/TokenSet")({
  accessToken: Schema.RedactedFromValue(Schema.String, { disallowEncode: true }),
  refreshToken: Schema.optional(Schema.RedactedFromValue(Schema.String, { disallowEncode: true })),
  expiresAt: Schema.Number
}) {}

/** Mask a CPF for display: first three and last two digits survive. */
export const maskCpf = (cpf: Cpf): string => `${cpf.slice(0, 3)}******${cpf.slice(9)}`
