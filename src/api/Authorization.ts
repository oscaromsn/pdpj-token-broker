import { Context, Schema } from "effect"
import { HttpApiMiddleware, HttpApiSecurity } from "effect/unstable/httpapi"
import type { TenantId } from "../domain/Model.ts"

/** The tenant the current request belongs to, injected by the middleware. */
export class CurrentTenant extends Context.Service<CurrentTenant, TenantId>()(
  "broker/api/CurrentTenant"
) {}

export class Unauthorized extends Schema.TaggedError<Unauthorized>()(
  "Unauthorized",
  { message: Schema.String },
  { httpApiStatus: 401 }
) {}

/**
 * Bearer-key authentication.
 *
 * Every endpoint is behind this, and it provides `CurrentTenant` downstream.
 * That is what makes cross-tenant access hard to write by accident: a handler
 * cannot name a tenant it was not given, because the only tenant in scope is
 * the authenticated one.
 */
export class Authorization extends HttpApiMiddleware.Service<Authorization, {
  provides: CurrentTenant
  requires: never
}>()("broker/api/Authorization", {
  security: { bearer: HttpApiSecurity.bearer },
  error: Unauthorized
}) {}
