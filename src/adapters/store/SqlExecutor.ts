import { Context, type Effect } from "effect"
import type { StoreUnavailable } from "../../ports/CredentialStore.ts"

/**
 * The narrowest possible seam over a SQL database.
 *
 * Cloudflare's `PreparedStatement` is a concrete class rather than an
 * interface, so an adapter written straight against it can only be exercised
 * with a live D1 binding. Putting this two-method seam at the very edge means
 * the schema, the SQL and the row mapping — where the bugs actually are — can
 * be tested against real SQLite, which is the same engine D1 runs. Only the
 * handful of lines that translate to `prepare().bind().all()` stay unverified
 * until deploy.
 */
export class SqlExecutor extends Context.Service<SqlExecutor, {
  all<T>(
    sql: string,
    params: ReadonlyArray<unknown>
  ): Effect.Effect<ReadonlyArray<T>, StoreUnavailable>

  run(sql: string, params: ReadonlyArray<unknown>): Effect.Effect<void, StoreUnavailable>
}>()("broker/adapters/store/SqlExecutor") {}
