import type { RuntimeContext } from "alchemy"
import * as Cloudflare from "alchemy/Cloudflare"
import { Config, Effect, Layer, Redacted } from "effect"
import { HttpRouter, HttpServer } from "effect/unstable/http"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import {
  BrowserServiceConfig,
  ContainerBrowserLogin
} from "./adapters/browser/ContainerBrowserLogin.ts"
import { KvTokenCache, type KvClient } from "./adapters/cache/KvTokenCache.ts"
import { KeycloakSso, layerHttp, SsoConfig } from "./adapters/sso/KeycloakSso.ts"
import { OtplibTotp } from "./adapters/sso/OtplibTotp.ts"
import { D1AuditLog } from "./adapters/store/D1AuditLog.ts"
import { D1CredentialStore } from "./adapters/store/D1CredentialStore.ts"
import { D1TenantAuth } from "./adapters/store/D1TenantAuth.ts"
import { SqlExecutor } from "./adapters/store/SqlExecutor.ts"
import { DerivedKeyRing, Kek } from "./adapters/vault/DerivedKeyRing.ts"
import { EncryptedVault } from "./adapters/vault/EncryptedVault.ts"
import { BrokerApi } from "./api/Credentials.ts"
import { TokenBroker } from "./broker/TokenBroker.ts"
import { StoreUnavailable } from "./ports/CredentialStore.ts"
import { AuthorizationLayer, CredentialsHandlersNoDeps, SystemHandlers } from "./server/Handlers.ts"
import { Database, TokenCacheNamespace } from "./infra/resources.ts"

const PDPJ_REALM = "https://sso.cloud.pje.jus.br/auth/realms/pje/protocol/openid-connect"

/**
 * The composition root.
 *
 * Everything above this file is written against ports; this is the single
 * place that knows those ports are backed by D1 and KV. Swapping any of them
 * is a change here and nowhere else — which is what made phases 1–5 testable
 * without a Cloudflare account.
 *
 * ## Init versus runtime
 *
 * The outer generator is the **init** phase: it runs at plantime to record
 * bindings, and again at each cold start. The `fetch` effect it returns is the
 * **runtime** phase.
 *
 * That split drives the shape below. Cloudflare's binding clients return
 * effects requiring Alchemy's `RuntimeContext`, and `RuntimeContext` exists
 * *only* at runtime — so the context is captured inside `fetch`, not at init,
 * and the whole adapter graph is built there. `Effect.cached` keeps that to
 * once per cold start rather than once per request.
 *
 * Secrets come from `Config.redacted`, which Alchemy binds onto the Worker as
 * `secret_text` automatically. That is why there is no secrets-store resource
 * here: the value is read from the deploying environment, bound at deploy
 * time, and never committed.
 */
export default class Broker extends Cloudflare.Worker<Broker>()(
  "Broker",
  {
    main: import.meta.url,
    compatibility: {
      // Required by otplib's crypto plugin.
      flags: ["nodejs_compat"],
      date: "2026-03-17"
    }
  },
  Effect.gen(function*() {
    // ── Init: bind resources and read configuration ───────────────────────
    const d1 = yield* Cloudflare.D1.QueryDatabase(Database)
    const kv = yield* Cloudflare.KV.ReadWriteNamespace(TokenCacheNamespace)

    // Evaluated here in init, so Alchemy binds each onto the Worker's
    // environment as a secret at deploy time.
    const masterKey = yield* Config.redacted("VAULT_MASTER_KEY")
    // Defaulted, so the broker deploys standalone before the browser
    // container exists. The fallback is only reached on `ChallengeRequired`;
    // until one is configured, that path fails as `SsoUnavailable` — which is
    // exactly right, since there is genuinely no browser to escalate to.
    const browserUrl = yield* Config.string("BROWSER_SERVICE_URL").pipe(
      Config.withDefault("http://browser-service-not-configured.invalid")
    )
    const browserToken = yield* Config.redacted("BROWSER_SERVICE_TOKEN").pipe(
      Config.withDefault(Redacted.make("not-configured"))
    )

    /**
     * Build the whole adapter graph and the request handler.
     *
     * Runs inside the runtime phase because it needs `RuntimeContext`.
     * Grounding each binding call against the captured context is what keeps
     * `RuntimeContext` out of the port interfaces — the alternative would be
     * threading a Cloudflare type through `CredentialStore` and into the
     * domain.
     */
    const buildHandler = Effect.gen(function*() {
      const runtime = yield* Effect.context<RuntimeContext>()
      const ground = <A, E>(effect: Effect.Effect<A, E, RuntimeContext>) =>
        effect.pipe(Effect.provide(runtime))

      const sqlExecutor = Layer.succeed(
        SqlExecutor,
        SqlExecutor.of({
          all: <T>(sql: string, params: ReadonlyArray<unknown>) =>
            ground(d1.prepare(sql).bind(...params).all<T>()).pipe(
              Effect.map((result) => result.results),
              Effect.mapError((cause) =>
                new StoreUnavailable({ detail: "D1 query failed", cause })
              )
            ),
          run: (sql: string, params: ReadonlyArray<unknown>) =>
            ground(d1.prepare(sql).bind(...params).run()).pipe(
              Effect.asVoid,
              Effect.mapError((cause) =>
                new StoreUnavailable({ detail: "D1 statement failed", cause })
              )
            )
        })
      )

      const kvClient: KvClient = {
        // A cache failure must not fail the request: the broker treats a miss
        // as "re-mint", which is strictly better than a 500.
        get: (key) => ground(kv.get(key, "text")).pipe(Effect.orElseSucceed(() => null)),
        put: (key, value, ttlSeconds) =>
          ground(kv.put(key, value, { expirationTtl: ttlSeconds })).pipe(Effect.ignore),
        delete: (key) => ground(kv.delete(key)).pipe(Effect.ignore)
      }

      const storage = Layer.mergeAll(
        D1CredentialStore.layer.pipe(Layer.provide(sqlExecutor)),
        D1TenantAuth.layer.pipe(Layer.provide(sqlExecutor)),
        D1AuditLog.layer.pipe(Layer.provide(sqlExecutor)),
        KvTokenCache.layerWith(kvClient)
      )

      const vault = EncryptedVault.layer.pipe(
        Layer.provide(
          Layer.mergeAll(
            D1CredentialStore.layer.pipe(Layer.provide(sqlExecutor)),
            DerivedKeyRing.layer.pipe(Layer.provide(Layer.succeed(Kek, masterKey)))
          )
        )
      )

      const sso = KeycloakSso.layer.pipe(
        Layer.provide(
          Layer.mergeAll(
            layerHttp,
            OtplibTotp.layer,
            Layer.succeed(
              SsoConfig,
              SsoConfig.of({
                realmUrl: PDPJ_REALM,
                clientId: "portalexterno-frontend",
                redirectUri: "https://portaldeservicos.pdpj.jus.br/consulta"
              })
            )
          )
        )
      )

      const browser = ContainerBrowserLogin.layer.pipe(
        Layer.provide(
          Layer.mergeAll(
            layerHttp,
            Layer.succeed(
              BrowserServiceConfig,
              BrowserServiceConfig.of({
                baseUrl: browserUrl,
                authToken: browserToken,
                timeoutMillis: 90_000
              })
            )
          )
        )
      )

      const infra = Layer.mergeAll(vault, storage, sso, browser)
      const brokerLayer = TokenBroker.layer.pipe(Layer.provide(infra))

      const routes = HttpApiBuilder.layer(BrokerApi).pipe(
        Layer.provide(
          CredentialsHandlersNoDeps.pipe(
            Layer.provide(
              Layer.mergeAll(
                infra,
                brokerLayer,
                AuthorizationLayer.pipe(Layer.provide(storage))
              )
            )
          )
        ),
        Layer.provide(SystemHandlers)
      )

      // Turns the router layer into the per-request effect `fetch` expects,
      // without standing up a server. `layerServices` supplies the platform
      // services the router needs (HttpPlatform and friends) so they do not
      // leak out as requirements on the Worker's handler.
      return yield* HttpRouter.toHttpEffect(
        routes.pipe(Layer.provide(HttpServer.layerServices))
      )
    })

    // Once per cold start, not once per request.
    const handler = yield* Effect.cached(buildHandler)

    return {
      // ── Runtime ────────────────────────────────────────────────────────
      fetch: Effect.gen(function*() {
        return yield* yield* handler
      })
    }
  }).pipe(
    // Each capability is a `Binding.Service` with two interchangeable
    // implementations: the native Worker binding, and a token-scoped HTTP
    // client. Providing the *Binding variants is what registers the binding at
    // deploy time and returns a live client at runtime.
    Effect.provide(Cloudflare.D1.QueryDatabaseBinding),
    Effect.provide(Cloudflare.KV.ReadWriteNamespaceBinding)
  )
) {}

