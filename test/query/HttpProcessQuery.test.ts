import { assert, describe, it } from "@effect/vitest"
import { Effect, Layer, Redacted, Ref, Schema } from "effect"
import { HttpClient, HttpClientResponse } from "effect/unstable/http"
import { HttpProcessQuery, ProcessApiConfig } from "../../src/query/HttpProcessQuery.ts"
import { ProcessNumber } from "../../src/domain/ProcessNumber.ts"
import { ProcessQuery } from "../../src/ports/ProcessQuery.ts"

/**
 * These tests pin the classification the live run taught us, especially the
 * three failures that look alike over the wire but must not be confused: a WAF
 * block (retry via browser), a no-standing refusal (do not retry), and a
 * genuinely rejected token (re-authenticate).
 */

const numero = Schema.decodeUnknownSync(ProcessNumber)("0801429-56.2022.4.05.8201")
const token = Redacted.make("the-access-token")

const configLayer = Layer.succeed(
  ProcessApiConfig,
  ProcessApiConfig.of({ baseUrl: "https://portaldeservicos.pdpj.jus.br/api/v2/processos" })
)

const withReply = (reply: { status: number; body: string } | { throws: true }) =>
  Effect.gen(function*() {
    const sent = yield* Ref.make<ReadonlyArray<{ url: string; auth: string | undefined; ua: string | undefined }>>([])
    const httpLayer = Layer.succeed(
      HttpClient.HttpClient,
      HttpClient.make((request) =>
        Effect.gen(function*() {
          yield* Ref.update(sent, (all) => [
            ...all,
            {
              url: request.url,
              auth: request.headers["authorization"],
              ua: request.headers["user-agent"]
            }
          ])
          if ("throws" in reply) {
            return yield* Effect.fail(
              // Simulate a reset connection the way the transport surfaces it.
              new Error("ECONNRESET") as never
            )
          }
          return HttpClientResponse.fromWeb(
            request,
            new Response(reply.body, { status: reply.status })
          )
        })
      )
    )
    const result = yield* Effect.result(
      Effect.gen(function*() {
        const query = yield* ProcessQuery
        return yield* query.byNumber(token, numero)
      }).pipe(Effect.provide(HttpProcessQuery.layer.pipe(Layer.provide(Layer.mergeAll(httpLayer, configLayer)))))
    )
    return { result, sent: yield* Ref.get(sent) } as const
  })

describe("HttpProcessQuery", () => {
  it.effect("returns the process JSON on 200", () =>
    Effect.gen(function*() {
      const { result, sent } = yield* withReply({ status: 200, body: "{\"numeroProcesso\":\"...\"}" })
      assert.isTrue(result._tag === "Success")
      if (result._tag !== "Success") return
      assert.strictEqual(result.success._tag, "Found")

      // The request must carry the browser headers, or the WAF blocks it.
      assert.include(sent[0]?.url ?? "", "08014295620224058201")
      assert.strictEqual(sent[0]?.auth, "Bearer the-access-token")
      assert.include(sent[0]?.ua ?? "", "Chrome")
    }))

  it.effect("reports a no-standing refusal from a 401 with the access message", () =>
    Effect.gen(function*() {
      const { result } = yield* withReply({
        status: 401,
        body: JSON.stringify({ status: 401, message: "Usuário não possui acesso ao processo 08014295620224058201" })
      })
      assert.isTrue(result._tag === "Success")
      if (result._tag !== "Success") return
      // A valid token, refused for this case — not a token problem.
      assert.strictEqual(result.success._tag, "NoStanding")
      if (result.success._tag === "NoStanding") {
        assert.include(result.success.message, "não possui acesso")
      }
    }))

  it.effect("reports the same no-standing from a 403 with the access message (filtered form)", () =>
    Effect.gen(function*() {
      const { result } = yield* withReply({
        status: 403,
        body: JSON.stringify({ message: "Usuário não possui acesso ao processo ..." })
      })
      assert.isTrue(result._tag === "Success")
      if (result._tag === "Success") assert.strictEqual(result.success._tag, "NoStanding")
    }))

  it.effect("treats a WAF HTML 403 as a retryable block, not a refusal", () =>
    Effect.gen(function*() {
      const { result } = yield* withReply({
        status: 403,
        body: "<html>\n<head><title>403 Forbidden</title></head>\n<body><center><h1>403 Forbidden</h1></center></body></html>"
      })
      assert.isTrue(result._tag === "Failure")
      if (result._tag !== "Failure") return
      // The token never reached the app; a browser context can get through.
      assert.strictEqual(result.failure._tag, "ProcessQueryBlocked")
    }))

  it.effect("treats a reset connection as a block", () =>
    Effect.gen(function*() {
      const { result } = yield* withReply({ throws: true })
      assert.isTrue(result._tag === "Failure")
      if (result._tag === "Failure") assert.strictEqual(result.failure._tag, "ProcessQueryBlocked")
    }))

  it.effect("distinguishes a genuinely rejected token from a no-standing refusal", () =>
    Effect.gen(function*() {
      const { result } = yield* withReply({
        status: 401,
        body: JSON.stringify({ status: 401, error: "Unauthorized", message: "" })
      })
      assert.isTrue(result._tag === "Failure")
      if (result._tag !== "Failure") return
      // No access message → the token itself is bad; re-authenticate.
      assert.strictEqual(result.failure._tag, "ProcessTokenRejected")
    }))

  it.effect("reports NotFound on a 404 without an access message", () =>
    Effect.gen(function*() {
      const { result } = yield* withReply({ status: 404, body: "{\"status\":404}" })
      assert.isTrue(result._tag === "Success")
      if (result._tag === "Success") assert.strictEqual(result.success._tag, "NotFound")
    }))

  it.effect("treats a 5xx as transient", () =>
    Effect.gen(function*() {
      const { result } = yield* withReply({ status: 502, body: "bad gateway" })
      assert.isTrue(result._tag === "Failure")
      if (result._tag === "Failure") assert.strictEqual(result.failure._tag, "ProcessQueryUnavailable")
    }))
})
