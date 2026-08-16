import { Effect, Layer } from "effect"
import type { CredentialId, TenantId } from "../../domain/Model.ts"
import { AuditLog, type AuditEvent } from "../../ports/AuditLog.ts"
import { SqlExecutor } from "./SqlExecutor.ts"

/** Everything about an event except its tag, as a JSON detail column. */
const detailOf = (event: AuditEvent): string | null => {
  switch (event._tag) {
    case "LoginSucceeded":
      return JSON.stringify({ viaBrowser: event.viaBrowser })
    case "LoginFailed":
      return JSON.stringify({ reason: event.reason })
    case "CircuitOpened":
      return JSON.stringify({ cooldownMillis: event.cooldownMillis })
    default:
      return null
  }
}

/**
 * `AuditLog` over the append-only `audit_log` table.
 *
 * Recording must never break a request that otherwise succeeded, so a write
 * failure is logged and swallowed rather than propagated. That is a deliberate
 * trade: an audit gap is bad, but failing a working login because the audit
 * insert timed out is worse, and the gap is visible in the logs.
 */
export class D1AuditLog {
  static readonly layer: Layer.Layer<AuditLog, never, SqlExecutor> = Layer.effect(
    AuditLog,
    Effect.gen(function*() {
      const sql = yield* SqlExecutor

      const record = Effect.fn("D1AuditLog.record")(
        function*(tenantId: TenantId, id: CredentialId, event: AuditEvent) {
          const at = yield* Effect.clockWith((clock) => clock.currentTimeMillis)
          yield* sql.run(
            `INSERT INTO audit_log (tenant_id, credential_id, event, detail, at)
             VALUES (?, ?, ?, ?, ?)`,
            [tenantId, id, event._tag, detailOf(event), at]
          ).pipe(
            Effect.catch((cause) =>
              Effect.logError("audit write failed", { tenantId, id, event: event._tag, cause })
            )
          )
        }
      )

      return AuditLog.of({ record })
    })
  )
}
