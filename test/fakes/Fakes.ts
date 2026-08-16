import { Effect, Layer, Option, Redacted, Ref, Schema } from "effect"
import { Cpf } from "../../src/domain/Cpf.ts"
import { ChallengeRequired, InvalidPassword, SsoUnavailable } from "../../src/domain/Errors.ts"
import { Credential, CredentialId, TenantId, TokenSet } from "../../src/domain/Model.ts"
import { TotpSeed } from "../../src/domain/TotpSeed.ts"
import { AuditLog, type AuditEvent } from "../../src/ports/AuditLog.ts"
import { CredentialVault } from "../../src/ports/CredentialVault.ts"
import { BrowserLogin, SsoClient } from "../../src/ports/SsoClient.ts"
import { TokenCache } from "../../src/ports/TokenCache.ts"
import { TotpGenerator } from "../../src/ports/TotpGenerator.ts"
import { CredentialRow, CredentialStore } from "../../src/ports/CredentialStore.ts"

/**
 * In-memory adapters for every port.
 *
 * These exist so the broker's decision cascade can be tested exhaustively with
 * no network, no database and no browser. Each fake also exposes a counter or
 * a script, because most of what we need to assert is not "what came back" but
 * "how many times did you call the SSO" — single-flight and the circuit
 * breaker are only observable through call counts.
 */

export const tenant = Schema.decodeUnknownSync(TenantId)("tenant-1")
export const credentialId = Schema.decodeUnknownSync(CredentialId)("cred-1")

export const testCredential = new Credential({
  id: credentialId,
  tenantId: tenant,
  cpf: Schema.decodeUnknownSync(Cpf)("52998224725"),
  password: Redacted.make("correct-horse"),
  totpSeed: Schema.decodeUnknownSync(TotpSeed)("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
})

export const tokenSet = (opts: {
  readonly access: string
  readonly refresh?: string | undefined
  readonly expiresAt: number
}): TokenSet =>
  new TokenSet({
    accessToken: Redacted.make(opts.access),
    refreshToken: opts.refresh === undefined ? undefined : Redacted.make(opts.refresh),
    expiresAt: opts.expiresAt
  })

/* ------------------------------------------------------------------ vault */

export const VaultFake = Layer.effect(
  CredentialVault,
  Effect.sync(() =>
    CredentialVault.of({
      get: () => Effect.succeed(testCredential),
      list: () => Effect.succeed([]),
      put: () => Effect.succeed(credentialId),
      setStatus: () => Effect.void
    })
  )
)

/* ------------------------------------------------------------------ cache */

export const makeCacheFake = Effect.gen(function*() {
  const store = yield* Ref.make(Option.none<TokenSet>())
  const layer = Layer.succeed(
    TokenCache,
    TokenCache.of({
      get: () => Ref.get(store),
      set: (_t, _i, tokens) => Ref.set(store, Option.some(tokens)),
      invalidate: () => Ref.set(store, Option.none())
    })
  )
  return { store, layer } as const
})

/* -------------------------------------------------------------------- sso */

/**
 * Build an SSO fake from an explicit behaviour, so each test states exactly
 * the SSO it is exercising rather than sharing one over-configured double.
 */
export const makeSsoFake = (behaviour: {
  readonly onLogin: (attempt: number) => Effect.Effect<TokenSet, InvalidPassword | SsoUnavailable | ChallengeRequired>
  readonly onRefresh?: ((attempt: number) => Effect.Effect<TokenSet, SsoUnavailable>) | undefined
  /** Artificial latency, so concurrent callers genuinely overlap. */
  readonly loginDelayMillis?: number | undefined
}) =>
  Effect.gen(function*() {
    const loginCalls = yield* Ref.make(0)
    const refreshCalls = yield* Ref.make(0)

    const layer = Layer.succeed(
      SsoClient,
      SsoClient.of({
        login: () =>
          Effect.gen(function*() {
            const attempt = yield* Ref.updateAndGet(loginCalls, (n) => n + 1)
            if (behaviour.loginDelayMillis !== undefined) {
              yield* Effect.sleep(behaviour.loginDelayMillis)
            }
            return yield* behaviour.onLogin(attempt)
          }),
        refresh: () =>
          Effect.gen(function*() {
            const attempt = yield* Ref.updateAndGet(refreshCalls, (n) => n + 1)
            return yield* (behaviour.onRefresh
              ? behaviour.onRefresh(attempt)
              : Effect.fail(new SsoUnavailable({ detail: "no refresh configured" })))
          })
      })
    )

    return { loginCalls, refreshCalls, layer } as const
  })

/* --------------------------------------------------------------- browser */

export const makeBrowserFake = (
  onLogin: (attempt: number) => Effect.Effect<TokenSet, InvalidPassword | SsoUnavailable>
) =>
  Effect.gen(function*() {
    const calls = yield* Ref.make(0)
    const layer = Layer.succeed(
      BrowserLogin,
      BrowserLogin.of({
        login: () =>
          Effect.gen(function*() {
            const attempt = yield* Ref.updateAndGet(calls, (n) => n + 1)
            return yield* onLogin(attempt)
          })
      })
    )
    return { calls, layer } as const
  })

/* ------------------------------------------------------------------ totp */

export const TotpFake = Layer.succeed(
  TotpGenerator,
  TotpGenerator.of({ generate: () => Effect.succeed("123456") })
)

/* ----------------------------------------------------------------- audit */

export const makeAuditFake = Effect.gen(function*() {
  const events = yield* Ref.make<ReadonlyArray<AuditEvent>>([])
  const layer = Layer.succeed(
    AuditLog,
    AuditLog.of({
      record: (_t, _i, event) => Ref.update(events, (all) => [...all, event])
    })
  )
  return { events, layer } as const
})

/* --------------------------------------------------- credential store */

/**
 * In-memory `CredentialStore`. Shared by the vault tests and the end-to-end
 * test so there is one definition of "storage that works", not two that can
 * drift apart.
 */
export const makeStoreFake = Effect.gen(function*() {
  const rows = yield* Ref.make<ReadonlyArray<CredentialRow>>([])
  const layer = Layer.succeed(
    CredentialStore,
    CredentialStore.of({
      find: (tenantId, id) =>
        Ref.get(rows).pipe(
          Effect.map((all) =>
            Option.fromNullishOr(all.find((r) => r.tenantId === tenantId && r.id === id))
          )
        ),
      all: (tenantId) =>
        Ref.get(rows).pipe(Effect.map((all) => all.filter((r) => r.tenantId === tenantId))),
      upsert: (row) =>
        Ref.update(rows, (all) => [
          ...all.filter((r) => !(r.tenantId === row.tenantId && r.id === row.id)),
          row
        ]),
      patchStatus: (tenantId, id, status, detail) =>
        Ref.update(rows, (all) =>
          all.map((r) =>
            r.tenantId === tenantId && r.id === id
              ? new CredentialRow({
                ...r,
                status,
                ...(detail === undefined ? {} : { lastError: detail })
              })
              : r
          ))
    })
  )
  return { rows, layer } as const
})

/** A master key long enough to satisfy DerivedKeyRing's minimum. */
export const testKek = "test-master-key-for-the-broker-suite-0001"
