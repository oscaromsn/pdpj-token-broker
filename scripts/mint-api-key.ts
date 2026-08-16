import { Effect, Layer, Redacted, Schema } from "effect"
import * as ApiKeys from "../src/admin/ApiKeys.ts"
import { SqlExecutor } from "../src/adapters/store/SqlExecutor.ts"
import { TenantId } from "../src/domain/Model.ts"
import { StoreUnavailable } from "../src/ports/CredentialStore.ts"

/**
 * Operator tool for tenant API keys.
 *
 * The broker authenticates every request against the `api_keys` table and
 * nothing in the deployed service writes to it — deliberately, because an
 * endpoint that mints credentials for arbitrary tenants would be the most
 * dangerous surface here and would itself need a bootstrap credential to
 * protect. This closes that loop from outside the network instead.
 *
 *   # against the deployed D1 database
 *   bun scripts/mint-api-key.ts mint --tenant acme --label "CI" \
 *     --account <cf-account-id> --database <d1-database-id>
 *
 *   # against a local SQLite file, for development
 *   bun scripts/mint-api-key.ts mint --tenant acme --label dev --sqlite ./dev.db
 *
 *   bun scripts/mint-api-key.ts list   [--tenant acme] ...
 *   bun scripts/mint-api-key.ts revoke --hash <key-hash> ...
 *
 * Remote mode needs `CLOUDFLARE_API_TOKEN` with D1 edit permission. The
 * account and database ids are printed by `alchemy deploy`, or readable with
 * `alchemy state get --stack PdpjTokenBroker`.
 */

const D1Response = Schema.Struct({
  success: Schema.Boolean,
  result: Schema.optional(
    Schema.Array(Schema.Struct({ results: Schema.optional(Schema.Array(Schema.Unknown)) }))
  ),
  errors: Schema.optional(Schema.Array(Schema.Struct({ message: Schema.String })))
})

const decodeD1 = Schema.decodeUnknownEffect(D1Response)

/** Talks to a deployed D1 database over Cloudflare's REST API. */
const remoteExecutor = (accountId: string, databaseId: string, token: string) => {
  const query = (sql: string, params: ReadonlyArray<unknown>) =>
    Effect.gen(function*() {
      const response = yield* Effect.tryPromise({
        try: () =>
          fetch(
            `https://api.cloudflare.com/client/v4/accounts/${accountId}/d1/database/${databaseId}/query`,
            {
              method: "POST",
              headers: {
                authorization: `Bearer ${token}`,
                "content-type": "application/json"
              },
              body: JSON.stringify({ sql, params })
            }
          ),
        catch: (cause) => new StoreUnavailable({ detail: "D1 API unreachable", cause })
      })

      const body = yield* Effect.tryPromise({
        try: () => response.json(),
        catch: (cause) => new StoreUnavailable({ detail: "D1 API sent no JSON", cause })
      })

      const decoded = yield* decodeD1(body).pipe(
        Effect.mapError((cause) =>
          new StoreUnavailable({ detail: "unexpected D1 API response", cause })
        )
      )

      if (!decoded.success) {
        const detail = decoded.errors?.map((e) => e.message).join("; ") ?? "unknown D1 error"
        return yield* new StoreUnavailable({ detail })
      }

      return decoded.result?.[0]?.results ?? []
    })

  return Layer.succeed(
    SqlExecutor,
    SqlExecutor.of({
      // SAFETY: D1 returns untyped column records; every caller decodes them
      // through a Schema before use.
      all: <T>(sql: string, params: ReadonlyArray<unknown>) =>
        query(sql, params).pipe(Effect.map((rows) => rows as ReadonlyArray<T>)),
      run: (sql: string, params: ReadonlyArray<unknown>) => query(sql, params).pipe(Effect.asVoid)
    })
  )
}

/**
 * Talks to a local SQLite file, for development.
 *
 * `node:sqlite` is imported lazily because Bun does not provide it. Keeping
 * the import inside this branch means the remote path — the one that actually
 * matters in production — runs under either runtime.
 */
const localExecutor = (path: string) =>
  Layer.unwrap(Effect.gen(function*() {
    const { DatabaseSync } = yield* Effect.tryPromise({
      try: () => import("node:sqlite"),
      catch: () =>
        new StoreUnavailable({
          detail:
            "--sqlite needs node:sqlite, which Bun does not provide. " +
            "Run this command with `node` instead of `bun`, or use remote mode."
        })
    }).pipe(
      Effect.tapError((error) => Effect.sync(() => console.error(`error: ${error.detail}`))),
      Effect.orDie
    )
    const db = new DatabaseSync(path)

    return Layer.succeed(
      SqlExecutor,
      SqlExecutor.of({
        all: <T>(sql: string, params: ReadonlyArray<unknown>) =>
          Effect.try({
            // SAFETY: as above — decoded through a Schema by the caller.
            try: () =>
              db.prepare(sql).all(...(params as ReadonlyArray<never>)) as ReadonlyArray<
                unknown
              > as ReadonlyArray<T>,
            catch: (cause) => new StoreUnavailable({ detail: "sqlite query failed", cause })
          }),
        run: (sql: string, params: ReadonlyArray<unknown>) =>
          Effect.try({
            try: () => {
              db.prepare(sql).run(...(params as ReadonlyArray<never>))
            },
            catch: (cause) => new StoreUnavailable({ detail: "sqlite statement failed", cause })
          })
      })
    )
  }))

const flag = (name: string): string | undefined => {
  const index = process.argv.indexOf(`--${name}`)
  return index === -1 ? undefined : process.argv[index + 1]
}

const die = (message: string): never => {
  console.error(`error: ${message}`)
  process.exit(1)
}

const executorLayer = () => {
  const sqlite = flag("sqlite")
  if (sqlite !== undefined) return localExecutor(sqlite)

  const accountId = flag("account") ?? process.env["CLOUDFLARE_ACCOUNT_ID"]
  const databaseId = flag("database") ?? process.env["CLOUDFLARE_D1_DATABASE_ID"]
  const token = process.env["CLOUDFLARE_API_TOKEN"]

  if (accountId === undefined || databaseId === undefined || token === undefined) {
    return die(
      "need --sqlite <path>, or --account/--database (or CLOUDFLARE_ACCOUNT_ID / " +
        "CLOUDFLARE_D1_DATABASE_ID) plus CLOUDFLARE_API_TOKEN"
    )
  }
  return remoteExecutor(accountId, databaseId, token)
}

const command = process.argv[2]

const program = Effect.gen(function*() {
  switch (command) {
    case "mint": {
      const tenant = flag("tenant") ?? die("--tenant is required")
      const label = flag("label") ?? die("--label is required")
      const tenantId = yield* Schema.decodeUnknownEffect(TenantId)(tenant).pipe(Effect.orDie)

      const minted = yield* ApiKeys.mint(tenantId, label)

      // Printed once, to stdout, and never stored. Everything explanatory goes
      // to stderr so the key can be piped somewhere safe:
      //   bun scripts/mint-api-key.ts mint ... > key.txt
      console.error(`tenant : ${minted.tenantId}`)
      console.error(`label  : ${minted.label}`)
      console.error(`hash   : ${minted.keyHash}`)
      console.error("")
      console.error("Shown once — it is not recoverable. Store it now.")
      console.log(Redacted.value(minted.key))
      return
    }

    case "list": {
      const tenant = flag("tenant")
      const tenantId = tenant === undefined
        ? undefined
        : yield* Schema.decodeUnknownEffect(TenantId)(tenant).pipe(Effect.orDie)

      const keys = yield* ApiKeys.list(tenantId)
      if (keys.length === 0) {
        console.error("(no keys)")
        return
      }
      for (const key of keys) {
        const state = key.revokedAt === undefined || key.revokedAt === null
          ? "active "
          : "revoked"
        console.log(`${state}  ${key.tenantId.padEnd(20)}  ${key.keyHash}  ${key.label}`)
      }
      return
    }

    case "revoke": {
      const hash = flag("hash") ?? die("--hash is required (see `list`)")
      yield* ApiKeys.revoke(hash)
      console.error(`revoked ${hash}`)
      return
    }

    default:
      return die("usage: mint-api-key.ts <mint|list|revoke> [flags] — see the file header")
  }
}).pipe(Effect.provide(executorLayer()))

Effect.runPromise(program).catch((error: unknown) => {
  console.error(error)
  process.exit(1)
})
