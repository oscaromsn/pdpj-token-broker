import { Schema } from "effect"

/**
 * The wire contract between the Worker and the browser container.
 *
 * Shared by both sides so a change to one is a type error in the other, rather
 * than a runtime surprise discovered only when a captcha finally appears.
 *
 * Note what this request carries: a plaintext CPF, password and TOTP seed. That
 * is unavoidable — something has to type them into a login form — but it means
 * the container sits inside the same trust boundary as the vault. It must never
 * be exposed publicly, must be reached over TLS, and authenticates with a shared
 * token so that being merely network-adjacent is not enough to ask it to log in
 * as someone.
 */
export class BrowserLoginRequest extends Schema.Class<BrowserLoginRequest>(
  "broker/browser/BrowserLoginRequest"
)({
  cpf: Schema.String,
  password: Schema.String,
  totpSeed: Schema.optional(Schema.String)
}) {}

/**
 * The container's reply, as a tagged union.
 *
 * The failure tags mirror the domain's, because the distinction between "wrong
 * password" and "wrong code" is exactly as load-bearing here as it is on the
 * HTTP path: one must never be retried, and they call for different fixes.
 */
export const BrowserLoginReply = Schema.Union([
  Schema.Struct({
    _tag: Schema.Literal("Success"),
    accessToken: Schema.String,
    refreshToken: Schema.optional(Schema.String),
    expiresAt: Schema.Number
  }),
  Schema.Struct({
    _tag: Schema.Literal("InvalidPassword"),
    detail: Schema.String
  }),
  Schema.Struct({
    _tag: Schema.Literal("InvalidTotp"),
    detail: Schema.String
  }),
  Schema.Struct({
    _tag: Schema.Literal("Failed"),
    detail: Schema.String
  })
])

export type BrowserLoginReply = typeof BrowserLoginReply.Type
