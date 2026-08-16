import { Context, type Effect, type Option, type Redacted } from "effect"
import type { TenantId } from "../domain/Model.ts"

/**
 * Port: turns an inbound API key into the tenant it belongs to.
 *
 * Returns `Option` rather than failing, because "no such key" is a routine
 * outcome at an internet-facing edge, not an exceptional one. The middleware
 * decides what an absent tenant means in HTTP terms; this port stays free of
 * status codes.
 */
export class TenantAuth extends Context.Service<TenantAuth, {
  resolve(apiKey: Redacted.Redacted<string>): Effect.Effect<Option.Option<TenantId>>
}>()("broker/ports/TenantAuth") {}
