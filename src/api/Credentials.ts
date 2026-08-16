import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup, HttpApiSchema, OpenApi } from "effect/unstable/httpapi"
import { Cpf } from "../domain/Cpf.ts"
import {
  CircuitOpen,
  CredentialNotFound,
  InvalidPassword,
  InvalidTotp,
  SsoUnavailable,
  VaultCorrupt,
  VaultUnavailable
} from "../domain/Errors.ts"
import { CredentialId, CredentialView } from "../domain/Model.ts"
import { TotpSeed } from "../domain/TotpSeed.ts"
import { Authorization } from "./Authorization.ts"

/**
 * What a caller sends to enroll a credential.
 *
 * The CPF and seed are parsed by the *domain* schemas, so a malformed CPF or
 * an unusably short seed is rejected at the edge with a 400 — before anything
 * is encrypted and stored. That is the whole reason enrollment validates
 * rather than trusting: the alternative is a credential that stores fine and
 * fails every login afterwards.
 */
export class EnrollRequest extends Schema.Class<EnrollRequest>("broker/api/EnrollRequest")({
  label: Schema.String.pipe(Schema.check(Schema.isMinLength(1))),
  cpf: Cpf,
  password: Schema.String.pipe(Schema.check(Schema.isMinLength(1))),
  totpSeed: Schema.optional(TotpSeed)
}) {}

/**
 * A minted token, as returned to the caller.
 *
 * `accessToken` is a plain string here, not `Redacted`: this is the one place
 * in the system that is *supposed* to emit the secret, so the unwrap happens
 * once, visibly, at the boundary. Everywhere else the `Redacted` types make
 * emitting it a type error.
 *
 * The refresh token is deliberately absent. It outlives the access token by a
 * wide margin, callers have no use for it, and handing it out would turn a
 * leaked response into long-lived access.
 */
export class IssuedToken extends Schema.Class<IssuedToken>("broker/api/IssuedToken")({
  accessToken: Schema.String,
  /** Absolute epoch millis, so a caller can cache without guessing. */
  expiresAt: Schema.Number
}) {}

/**
 * Status codes are applied here, at the API boundary, rather than annotated
 * onto the domain errors. The domain does not know it is being served over
 * HTTP, and keeping it that way is what lets the same errors drive a CLI or a
 * queue consumer later.
 */
export class CredentialsApiGroup extends HttpApiGroup.make("credentials")
  .add(
    HttpApiEndpoint.post("enroll", "/", {
      payload: EnrollRequest,
      success: CredentialView,
      error: VaultUnavailable.pipe(HttpApiSchema.status(503))
    }),
    HttpApiEndpoint.get("list", "/", {
      success: Schema.Array(CredentialView),
      error: VaultUnavailable.pipe(HttpApiSchema.status(503))
    }),
    HttpApiEndpoint.post("issue", "/:id/token", {
      params: { id: CredentialId },
      success: IssuedToken,
      error: [
        CredentialNotFound.pipe(HttpApiSchema.status(404)),
        // The stored credential is bad and a human must re-enroll it. Not a
        // client error and not retryable, which 422 conveys and 400 does not.
        InvalidPassword.pipe(HttpApiSchema.status(422)),
        InvalidTotp.pipe(HttpApiSchema.status(422)),
        // 429 carries "come back later" semantics natively, which is exactly
        // what an open breaker means.
        CircuitOpen.pipe(HttpApiSchema.status(429)),
        // The failure is upstream at the SSO, not in this service.
        SsoUnavailable.pipe(HttpApiSchema.status(502)),
        VaultCorrupt.pipe(HttpApiSchema.status(500)),
        VaultUnavailable.pipe(HttpApiSchema.status(503))
      ]
    })
  )
  .middleware(Authorization)
  .prefix("/credentials")
  .annotateMerge(OpenApi.annotations({
    title: "Credentials",
    description: "Enroll court credentials and mint PDPJ access tokens from them"
  }))
{}

export class SystemApiGroup extends HttpApiGroup.make("system")
  .add(HttpApiEndpoint.get("health", "/health", { success: Schema.Void }))
{}

export class BrokerApi extends HttpApi.make("pdpj-token-broker")
  .add(CredentialsApiGroup)
  .add(SystemApiGroup)
  .annotateMerge(OpenApi.annotations({
    title: "PDPJ Token Broker",
    description: "Exchange stored court credentials for short-lived PDPJ access tokens"
  }))
{}
