import { assert, describe, it } from "@effect/vitest"
import { Effect, Layer, Option, Redacted, Ref } from "effect"
import { ChallengeRequired, InvalidPassword, SsoUnavailable } from "../../src/domain/Errors.ts"
import { TokenBroker } from "../../src/broker/TokenBroker.ts"
import type { AuditLog } from "../../src/ports/AuditLog.ts"
import type { BrowserLogin, SsoClient } from "../../src/ports/SsoClient.ts"
import type { TokenCache } from "../../src/ports/TokenCache.ts"
import {
  credentialId,
  makeAuditFake,
  makeBrowserFake,
  makeCacheFake,
  makeSsoFake,
  tenant,
  tokenSet,
  TotpFake,
  VaultFake
} from "../fakes/Fakes.ts"

/**
 * The cascade is the product. Every rung is asserted here against fakes, so
 * these tests run in milliseconds and cover the paths that are hardest to
 * exercise against a live SSO — notably the ones we must never trigger in
 * production, like repeated bad-password attempts.
 */

const FAR_FUTURE = 9_999_999_999_999

describe("TokenBroker", () => {
  it.effect("returns a cached token without touching the SSO", () =>
    Effect.gen(function*() {
      const cache = yield* makeCacheFake
      const sso = yield* makeSsoFake({
        onLogin: () => Effect.succeed(tokenSet({ access: "from-login", expiresAt: FAR_FUTURE }))
      })
      const audit = yield* makeAuditFake
      const browser = yield* makeBrowserFake(() =>
        Effect.fail(new SsoUnavailable({ detail: "unused" }))
      )

      yield* Ref.set(
        cache.store,
        Option.some(tokenSet({ access: "cached", expiresAt: FAR_FUTURE }))
      )

      const token = yield* Effect.gen(function*() {
        const broker = yield* TokenBroker
        return yield* broker.issue(tenant, credentialId)
      }).pipe(
        Effect.provide(
          TokenBroker.layer.pipe(
            Layer.provide(Layer.mergeAll(
              VaultFake,
              cache.layer,
              sso.layer,
              browser.layer,
              TotpFake,
              audit.layer
            ))
          )
        )
      )

      assert.strictEqual(Redacted.value(token.accessToken), "cached")
      assert.strictEqual(yield* Ref.get(sso.loginCalls), 0)
    }))

  it.effect("refreshes rather than logging in when the cached token is stale", () =>
    Effect.gen(function*() {
      const cache = yield* makeCacheFake
      const sso = yield* makeSsoFake({
        onLogin: () => Effect.succeed(tokenSet({ access: "from-login", expiresAt: FAR_FUTURE })),
        onRefresh: () => Effect.succeed(tokenSet({ access: "refreshed", expiresAt: FAR_FUTURE }))
      })
      const audit = yield* makeAuditFake
      const browser = yield* makeBrowserFake(() =>
        Effect.fail(new SsoUnavailable({ detail: "unused" }))
      )

      // Expired access token, but a usable refresh token.
      yield* Ref.set(
        cache.store,
        Option.some(tokenSet({ access: "stale", refresh: "rt", expiresAt: 0 }))
      )

      const token = yield* Effect.gen(function*() {
        const broker = yield* TokenBroker
        return yield* broker.issue(tenant, credentialId)
      }).pipe(
        Effect.provide(
          TokenBroker.layer.pipe(
            Layer.provide(Layer.mergeAll(
              VaultFake,
              cache.layer,
              sso.layer,
              browser.layer,
              TotpFake,
              audit.layer
            ))
          )
        )
      )

      assert.strictEqual(Redacted.value(token.accessToken), "refreshed")
      // The whole point: refreshing must not re-trigger a full login (and 2FA).
      assert.strictEqual(yield* Ref.get(sso.loginCalls), 0)
      assert.strictEqual(yield* Ref.get(sso.refreshCalls), 1)
    }))

  it.effect("falls through to a full login when refresh fails", () =>
    Effect.gen(function*() {
      const cache = yield* makeCacheFake
      const sso = yield* makeSsoFake({
        onLogin: () => Effect.succeed(tokenSet({ access: "from-login", expiresAt: FAR_FUTURE })),
        onRefresh: () => Effect.fail(new SsoUnavailable({ detail: "refresh rejected" }))
      })
      const audit = yield* makeAuditFake
      const browser = yield* makeBrowserFake(() =>
        Effect.fail(new SsoUnavailable({ detail: "unused" }))
      )

      yield* Ref.set(
        cache.store,
        Option.some(tokenSet({ access: "stale", refresh: "rt", expiresAt: 0 }))
      )

      const token = yield* Effect.gen(function*() {
        const broker = yield* TokenBroker
        return yield* broker.issue(tenant, credentialId)
      }).pipe(
        Effect.provide(
          TokenBroker.layer.pipe(
            Layer.provide(Layer.mergeAll(
              VaultFake,
              cache.layer,
              sso.layer,
              browser.layer,
              TotpFake,
              audit.layer
            ))
          )
        )
      )

      assert.strictEqual(Redacted.value(token.accessToken), "from-login")
      assert.strictEqual(yield* Ref.get(sso.loginCalls), 1)
    }))

  // `it.live` rather than `it.effect`: this test relies on a real sleep inside
  // the SSO fake to keep the ten callers genuinely overlapping. Under the
  // TestClock that sleep would never elapse and the test would hang.
  it.live("collapses concurrent misses into a single login (single-flight)", () =>
    Effect.gen(function*() {
      const cache = yield* makeCacheFake
      const sso = yield* makeSsoFake({
        onLogin: () => Effect.succeed(tokenSet({ access: "from-login", expiresAt: FAR_FUTURE })),
        // Overlap the callers so they are genuinely in flight together.
        loginDelayMillis: 50
      })
      const audit = yield* makeAuditFake
      const browser = yield* makeBrowserFake(() =>
        Effect.fail(new SsoUnavailable({ detail: "unused" }))
      )

      const loginCount = yield* Effect.gen(function*() {
        const broker = yield* TokenBroker
        // Ten callers stampede a cold cache at once.
        yield* Effect.all(
          Array.from({ length: 10 }, () => broker.issue(tenant, credentialId)),
          { concurrency: "unbounded" }
        )
        return yield* Ref.get(sso.loginCalls)
      }).pipe(
        Effect.provide(
          TokenBroker.layer.pipe(
            Layer.provide(Layer.mergeAll(
              VaultFake,
              cache.layer,
              sso.layer,
              browser.layer,
              TotpFake,
              audit.layer
            ))
          )
        )
      )

      // Hammering the SSO is what locks accounts. Ten callers, one login.
      assert.strictEqual(loginCount, 1)
    }))

  it.effect("never retries a rejected password, and reports it as terminal", () =>
    Effect.gen(function*() {
      const cache = yield* makeCacheFake
      const sso = yield* makeSsoFake({
        onLogin: () =>
          Effect.fail(
            new InvalidPassword({ credentialId, detail: "Usuário ou senha inválido" })
          )
      })
      const audit = yield* makeAuditFake
      const browser = yield* makeBrowserFake(() =>
        Effect.fail(new SsoUnavailable({ detail: "unused" }))
      )

      const { calls, result } = yield* Effect.gen(function*() {
        const broker = yield* TokenBroker
        const result = yield* Effect.result(broker.issue(tenant, credentialId))
        return { calls: yield* Ref.get(sso.loginCalls), result }
      }).pipe(
        Effect.provide(
          TokenBroker.layer.pipe(
            Layer.provide(Layer.mergeAll(
              VaultFake,
              cache.layer,
              sso.layer,
              browser.layer,
              TotpFake,
              audit.layer
            ))
          )
        )
      )

      assert.isTrue(result._tag === "Failure")
      // Exactly one attempt: a wrong password must never be retried.
      assert.strictEqual(calls, 1)
    }))

  it.effect("opens the circuit after repeated failures instead of calling again", () =>
    Effect.gen(function*() {
      const cache = yield* makeCacheFake
      const sso = yield* makeSsoFake({
        onLogin: () => Effect.fail(new SsoUnavailable({ detail: "boom" }))
      })
      const audit = yield* makeAuditFake
      const browser = yield* makeBrowserFake(() =>
        Effect.fail(new SsoUnavailable({ detail: "unused" }))
      )

      const { calls, lastTag } = yield* Effect.gen(function*() {
        const broker = yield* TokenBroker
        // Drive past the failure threshold, then attempt once more.
        for (let i = 0; i < 4; i++) {
          yield* Effect.result(broker.issue(tenant, credentialId))
        }
        const last = yield* Effect.result(broker.issue(tenant, credentialId))
        return {
          calls: yield* Ref.get(sso.loginCalls),
          lastTag: last._tag === "Failure" ? last.failure._tag : "Success"
        }
      }).pipe(
        Effect.provide(
          TokenBroker.layer.pipe(
            Layer.provide(Layer.mergeAll(
              VaultFake,
              cache.layer,
              sso.layer,
              browser.layer,
              TotpFake,
              audit.layer
            ))
          )
        )
      )

      assert.strictEqual(lastTag, "CircuitOpen")
      // Once open, the breaker must stop reaching the SSO entirely.
      assert.isTrue(calls < 5)
    }))

  it.effect("caches a freshly minted token so the next call is free", () =>
    Effect.gen(function*() {
      const cache = yield* makeCacheFake
      const sso = yield* makeSsoFake({
        onLogin: () => Effect.succeed(tokenSet({ access: "minted", expiresAt: FAR_FUTURE }))
      })
      const audit = yield* makeAuditFake
      const browser = yield* makeBrowserFake(() =>
        Effect.fail(new SsoUnavailable({ detail: "unused" }))
      )

      const calls = yield* Effect.gen(function*() {
        const broker = yield* TokenBroker
        yield* broker.issue(tenant, credentialId)
        yield* broker.issue(tenant, credentialId)
        return yield* Ref.get(sso.loginCalls)
      }).pipe(
        Effect.provide(
          TokenBroker.layer.pipe(
            Layer.provide(Layer.mergeAll(
              VaultFake,
              cache.layer,
              sso.layer,
              browser.layer,
              TotpFake,
              audit.layer
            ))
          )
        )
      )

      assert.strictEqual(calls, 1)
    }))
})

/**
 * The escalation contract between the HTTP transport and the browser fallback.
 * Getting this wrong in either direction is costly: never escalating makes the
 * browser dead weight, and escalating on the wrong error spends a real
 * account's lockout budget on an attempt that cannot succeed.
 */
describe("TokenBroker escalation", () => {
  const infraFor = (
    sso: Layer.Layer<SsoClient>,
    browser: Layer.Layer<BrowserLogin>,
    cache: Layer.Layer<TokenCache>,
    audit: Layer.Layer<AuditLog>
  ) =>
    TokenBroker.layer.pipe(
      Layer.provide(Layer.mergeAll(VaultFake, cache, sso, browser, TotpFake, audit))
    )

  it.effect("hands a challenge to the browser and returns its token", () =>
    Effect.gen(function*() {
      const cache = yield* makeCacheFake
      const audit = yield* makeAuditFake
      const sso = yield* makeSsoFake({
        onLogin: () => Effect.fail(new ChallengeRequired({ detail: "captcha" }))
      })
      const browser = yield* makeBrowserFake(() =>
        Effect.succeed(tokenSet({ access: "via-browser", expiresAt: FAR_FUTURE }))
      )

      const { token, browserCalls } = yield* Effect.gen(function*() {
        const broker = yield* TokenBroker
        const token = yield* broker.issue(tenant, credentialId)
        return { token, browserCalls: yield* Ref.get(browser.calls) }
      }).pipe(Effect.provide(infraFor(sso.layer, browser.layer, cache.layer, audit.layer)))

      assert.strictEqual(Redacted.value(token.accessToken), "via-browser")
      assert.strictEqual(browserCalls, 1)
    }))

  it.effect("does not escalate a rejected password to the browser", () =>
    Effect.gen(function*() {
      const cache = yield* makeCacheFake
      const audit = yield* makeAuditFake
      const sso = yield* makeSsoFake({
        onLogin: () =>
          Effect.fail(new InvalidPassword({ credentialId, detail: "senha inválida" }))
      })
      const browser = yield* makeBrowserFake(() =>
        Effect.succeed(tokenSet({ access: "via-browser", expiresAt: FAR_FUTURE }))
      )

      const { result, browserCalls } = yield* Effect.gen(function*() {
        const broker = yield* TokenBroker
        const result = yield* Effect.result(broker.issue(tenant, credentialId))
        return { result, browserCalls: yield* Ref.get(browser.calls) }
      }).pipe(Effect.provide(infraFor(sso.layer, browser.layer, cache.layer, audit.layer)))

      assert.isTrue(result._tag === "Failure")
      // A browser would be rejected identically; the extra attempt would only
      // spend the account's lockout budget.
      assert.strictEqual(browserCalls, 0)
    }))

  it.effect("records that the token came via the browser, for auditing", () =>
    Effect.gen(function*() {
      const cache = yield* makeCacheFake
      const audit = yield* makeAuditFake
      const sso = yield* makeSsoFake({
        onLogin: () => Effect.fail(new ChallengeRequired({ detail: "captcha" }))
      })
      const browser = yield* makeBrowserFake(() =>
        Effect.succeed(tokenSet({ access: "via-browser", expiresAt: FAR_FUTURE }))
      )

      const events = yield* Effect.gen(function*() {
        const broker = yield* TokenBroker
        yield* broker.issue(tenant, credentialId)
        return yield* Ref.get(audit.events)
      }).pipe(Effect.provide(infraFor(sso.layer, browser.layer, cache.layer, audit.layer)))

      // Exactly one success event, and it must say the browser was used.
      // An audit trail that double-counts a login, or that also claims the
      // same login went over HTTP, is worse than none.
      const successes = events.filter((e) => e._tag === "LoginSucceeded")
      assert.strictEqual(successes.length, 1, `saw ${JSON.stringify(successes)}`)
      assert.isTrue(
        successes[0]?._tag === "LoginSucceeded" && successes[0].viaBrowser,
        "a browser-assisted login must be distinguishable in the audit trail"
      )
    }))
})
