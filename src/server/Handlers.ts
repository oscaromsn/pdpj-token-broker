import { Effect, Layer, Option, Redacted } from "effect"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import { Authorization, CurrentTenant, Unauthorized } from "../api/Authorization.ts"
import { BrokerApi, IssuedToken } from "../api/Credentials.ts"
import { TokenBroker } from "../broker/TokenBroker.ts"
import { Credential, maskCpf } from "../domain/Model.ts"
import { CredentialVault } from "../ports/CredentialVault.ts"
import { TenantAuth } from "../ports/TenantAuth.ts"

/**
 * Bearer-key middleware.
 *
 * Kept apart from the `Authorization` service definition so the API contract
 * can be shared with clients without dragging the vault and the key store
 * along with it.
 */
export const AuthorizationLayer = Layer.effect(
  Authorization,
  // `TenantAuth` is resolved once here, at layer construction, rather than
  // inside the request handler. A middleware handler may only require the
  // services the router provides, so acquiring it per-request would not type.
  Effect.gen(function*() {
    const auth = yield* TenantAuth

    return Authorization.of({
      bearer: Effect.fn("Authorization.bearer")(function*(httpEffect, { credential }) {
        const tenant = yield* auth.resolve(credential)

        if (Option.isNone(tenant)) {
          // Deliberately uninformative: distinguishing "unknown key" from
          // "revoked key" would let an attacker enumerate valid keys.
          return yield* new Unauthorized({ message: "Invalid API key" })
        }

        return yield* Effect.provideService(httpEffect, CurrentTenant, tenant.value)
      })
    })
  })
)

/**
 * Credential endpoints.
 *
 * Every handler reads its tenant from `CurrentTenant` rather than from the
 * request, so there is no path by which a caller can name someone else's
 * tenant — the parameter simply does not exist in the API surface.
 */
export const CredentialsHandlersNoDeps = HttpApiBuilder.group(
  BrokerApi,
  "credentials",
  Effect.fn(function*(handlers) {
    const vault = yield* CredentialVault
    const broker = yield* TokenBroker

    return handlers.handleAll({
      enroll: Effect.fn(function*({ payload }) {
        const tenantId = yield* CurrentTenant

        // The id is generated here, never accepted from the caller: letting a
        // client choose it would allow overwriting another credential in the
        // same tenant.
        const id = yield* Effect.sync(() => crypto.randomUUID()).pipe(
          Effect.map((raw) => raw as Credential["id"])
        )

        yield* vault.put(
          new Credential({
            id,
            tenantId,
            cpf: payload.cpf,
            password: Redacted.make(payload.password),
            ...(payload.totpSeed === undefined ? {} : { totpSeed: payload.totpSeed })
          }),
          payload.label
        )

        // Reflect the stored state back rather than echoing the request, so
        // the caller sees the real lifecycle status (`validating`, not
        // `active` — nothing has proven this credential yet).
        const views = yield* vault.list(tenantId)
        const stored = views.find((view) => view.id === id)
        if (stored === undefined) {
          return yield* Effect.die("credential vanished immediately after being stored")
        }
        return stored
      }),

      list: () =>
        Effect.gen(function*() {
          const tenantId = yield* CurrentTenant
          return yield* vault.list(tenantId)
        }),

      issue: Effect.fn(function*({ params }) {
        const tenantId = yield* CurrentTenant
        const tokens = yield* broker.issue(tenantId, params.id)

        // The single, deliberate place where a secret is unwrapped for
        // output. Everywhere else `Redacted` makes this a type error.
        return new IssuedToken({
          accessToken: Redacted.value(tokens.accessToken),
          expiresAt: tokens.expiresAt
        })
      })
    })
  })
)

export const SystemHandlers = HttpApiBuilder.group(
  BrokerApi,
  "system",
  Effect.fn(function*(handlers) {
    return handlers.handleAll({
      health: () => Effect.void
    })
  })
)

/** Re-exported so tests can build views without importing the domain twice. */
export { maskCpf }
