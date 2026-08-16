import { Schema } from "effect"

/**
 * Wire contract for querying a process through the browser container.
 *
 * The container already runs a real Chromium for the login fallback; the same
 * browser is what clears the process-API WAF, since a request issued from a
 * genuine page carries the browser's TLS fingerprint that headers alone cannot
 * fake. So the query rides the same container over the same authenticated
 * channel.
 *
 * Unlike the login request, this one carries only a short-lived *access token*
 * — not the CPF/password/seed — so a leak here costs minutes of read access,
 * not an account. It is still inside the trust boundary and still authenticated
 * with the shared service token.
 */
export class BrowserQueryRequest extends Schema.Class<BrowserQueryRequest>(
  "broker/query/BrowserQueryRequest"
)({
  /** The PDPJ access token to present as Bearer. */
  accessToken: Schema.String,
  /** Fully-qualified process API URL to fetch, e.g. `.../api/v2/processos/<20 digits>`. */
  url: Schema.String
}) {}

/** What the container's page fetch observed. The Worker maps it to a ProcessResult. */
export class BrowserQueryReply extends Schema.Class<BrowserQueryReply>(
  "broker/query/BrowserQueryReply"
)({
  status: Schema.Number,
  body: Schema.String
}) {}
