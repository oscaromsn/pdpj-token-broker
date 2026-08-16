import { Context, type Effect, type Redacted, Schema } from "effect"
import type { ProcessNumber } from "../domain/ProcessNumber.ts"

/**
 * The outcome of a process query, as a tagged union.
 *
 * The distinction between the last two is the whole reason this is not just a
 * status code. `NoStanding` is a *valid* token that the court refuses for this
 * case — proven live: PDPJ answers "Usuário não possui acesso" (as a 401 for a
 * single process, a 403 for a filtered list). A browser retry would be refused
 * identically, so a caller must not treat it as a transport failure. `Blocked`
 * is the opposite: the token never reached the application because the gateway
 * WAF rejected the request shape — that one *does* warrant retrying through a
 * browser context.
 */
export type ProcessResult =
  | { readonly _tag: "Found"; readonly json: string }
  | { readonly _tag: "NoStanding"; readonly message: string }
  | { readonly _tag: "NotFound" }

/** The token was genuinely rejected (expired / malformed), not merely unauthorized for a case. */
export class ProcessTokenRejected extends Schema.TaggedError<ProcessTokenRejected>()(
  "ProcessTokenRejected",
  { detail: Schema.String }
) {}

/**
 * The PDPJ gateway blocked the request before the application saw it — a WAF
 * 403 HTML page or a reset connection. Retryable through a browser context;
 * NOT a statement about the token or the case.
 */
export class ProcessQueryBlocked extends Schema.TaggedError<ProcessQueryBlocked>()(
  "ProcessQueryBlocked",
  { detail: Schema.String }
) {}

/** A transient upstream failure (5xx, network). */
export class ProcessQueryUnavailable extends Schema.TaggedError<ProcessQueryUnavailable>()(
  "ProcessQueryUnavailable",
  { detail: Schema.String, cause: Schema.optional(Schema.Defect()) }
) {}

export type ProcessQueryError =
  | ProcessTokenRejected
  | ProcessQueryBlocked
  | ProcessQueryUnavailable

/**
 * Port: query the PDPJ process API with an access token.
 *
 * The token is `Redacted` so it cannot be logged on the way through. The port
 * knows nothing about *how* the request is made — plain HTTP, or driven
 * through a real browser to clear the WAF — which is exactly the seam the
 * live test showed we need: the same query, two transports, chosen by whether
 * the cheap one is being blocked.
 */
export class ProcessQuery extends Context.Service<ProcessQuery, {
  byNumber(
    token: Redacted.Redacted<string>,
    numero: ProcessNumber
  ): Effect.Effect<ProcessResult, ProcessQueryError>
}>()("broker/ports/ProcessQuery") {}
