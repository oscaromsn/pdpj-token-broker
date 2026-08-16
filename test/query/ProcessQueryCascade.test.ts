import { assert, describe, it } from "@effect/vitest"
import { Effect, Layer, Redacted, Ref, Schema } from "effect"
import { ProcessNumber } from "../../src/domain/ProcessNumber.ts"
import {
  ProcessQuery,
  ProcessQueryBlocked,
  ProcessTokenRejected,
  type ProcessResult
} from "../../src/ports/ProcessQuery.ts"
import { BrowserQuery, HttpQuery, ProcessQueryCascade } from "../../src/query/ProcessQueryCascade.ts"

/**
 * The cascade's only job is choosing when to escalate, so the tests count
 * calls: the browser transport must be reached only when the HTTP one is
 * blocked, and never for an answer a browser could not change.
 */

const numero = Schema.decodeUnknownSync(ProcessNumber)("0801429-56.2022.4.05.8201")
const token = Redacted.make("t")

/** A ProcessQuery that returns a scripted result and counts its calls. */
const stub = (
  outcome: Effect.Effect<ProcessResult, ProcessQueryBlocked | ProcessTokenRejected>
) =>
  Effect.gen(function*() {
    const calls = yield* Ref.make(0)
    const service = ProcessQuery.of({
      byNumber: () => Ref.update(calls, (n) => n + 1).pipe(Effect.andThen(outcome))
    })
    return { calls, service } as const
  })

const run = (
  httpService: ProcessQuery["Service"],
  browserService: ProcessQuery["Service"]
) =>
  Effect.gen(function*() {
    const query = yield* ProcessQuery
    return yield* Effect.result(query.byNumber(token, numero))
  }).pipe(
    Effect.provide(
      ProcessQueryCascade.layer.pipe(
        Layer.provide(
          Layer.mergeAll(
            Layer.succeed(HttpQuery, httpService),
            Layer.succeed(BrowserQuery, browserService)
          )
        )
      )
    )
  )

describe("ProcessQueryCascade", () => {
  it.effect("uses only HTTP when HTTP succeeds", () =>
    Effect.gen(function*() {
      const http = yield* stub(Effect.succeed({ _tag: "Found", json: "{}" }))
      const browser = yield* stub(Effect.succeed({ _tag: "Found", json: "browser" }))

      const result = yield* run(http.service, browser.service)

      assert.isTrue(result._tag === "Success")
      assert.strictEqual(yield* Ref.get(http.calls), 1)
      assert.strictEqual(yield* Ref.get(browser.calls), 0)
    }))

  it.effect("escalates to the browser when HTTP is WAF-blocked", () =>
    Effect.gen(function*() {
      const http = yield* stub(Effect.fail(new ProcessQueryBlocked({ detail: "waf" })))
      const browser = yield* stub(Effect.succeed({ _tag: "Found", json: "via-browser" }))

      const result = yield* run(http.service, browser.service)

      assert.isTrue(result._tag === "Success")
      if (result._tag === "Success") {
        assert.strictEqual(result.success._tag, "Found")
        if (result.success._tag === "Found") assert.strictEqual(result.success.json, "via-browser")
      }
      assert.strictEqual(yield* Ref.get(browser.calls), 1)
    }))

  it.effect("does NOT escalate a no-standing result", () =>
    Effect.gen(function*() {
      const http = yield* stub(Effect.succeed({ _tag: "NoStanding", message: "não possui acesso" }))
      const browser = yield* stub(Effect.succeed({ _tag: "Found", json: "should not run" }))

      const result = yield* run(http.service, browser.service)

      assert.isTrue(result._tag === "Success")
      if (result._tag === "Success") assert.strictEqual(result.success._tag, "NoStanding")
      // A browser would be refused identically — escalating would only be slow.
      assert.strictEqual(yield* Ref.get(browser.calls), 0)
    }))

  it.effect("does NOT escalate a rejected token", () =>
    Effect.gen(function*() {
      const http = yield* stub(Effect.fail(new ProcessTokenRejected({ detail: "expired" })))
      const browser = yield* stub(Effect.succeed({ _tag: "Found", json: "should not run" }))

      const result = yield* run(http.service, browser.service)

      assert.isTrue(result._tag === "Failure")
      if (result._tag === "Failure") assert.strictEqual(result.failure._tag, "ProcessTokenRejected")
      // No transport fixes a bad token.
      assert.strictEqual(yield* Ref.get(browser.calls), 0)
    }))
})
