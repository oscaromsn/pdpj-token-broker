import { Context, type Effect } from "effect"
import type { CredentialId, TenantId } from "../domain/Model.ts"

/** What happened to a credential. Append-only; never mutated. */
export type AuditEvent =
  | { readonly _tag: "TokenIssuedFromCache" }
  | { readonly _tag: "TokenRefreshed" }
  | { readonly _tag: "LoginSucceeded"; readonly viaBrowser: boolean }
  | { readonly _tag: "LoginFailed"; readonly reason: string }
  | { readonly _tag: "CircuitOpened"; readonly cooldownMillis: number }

/**
 * Port: the record of every credential use.
 *
 * Required, not optional: the broker holds credentials that can open sealed
 * case files, so "who used this, when" is the difference between a delegated
 * capability and an untraceable one. Writing the record is part of using a
 * credential, which is why the broker calls this on every path.
 */
export class AuditLog extends Context.Service<AuditLog, {
  record(
    tenantId: TenantId,
    id: CredentialId,
    event: AuditEvent
  ): Effect.Effect<void>
}>()("broker/ports/AuditLog") {}
