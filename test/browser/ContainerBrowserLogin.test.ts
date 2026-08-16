import { assert, describe, it } from "@effect/vitest"
import { Effect, Layer, Redacted, Ref, Schema } from "effect"
import { HttpClient, HttpClientResponse } from "effect/unstable/http"
import {
  BrowserServiceConfig,
  ContainerBrowserLogin
} from "../../src/adapters/browser/ContainerBrowserLogin.ts"
import { Cpf } from "../../src/domain/Cpf.ts"
import { Credential, CredentialId, TenantId } from "../../src/domain/Model.ts"
import { TotpSeed } from "../../src/domain/TotpSeed.ts"
import { BrowserLogin } from "../../src/ports/SsoClient.ts"

const credential = new Credential({
  id: Schema.decodeUnknownSync(CredentialId)("cred-1"),
  tenantId: Schema.decodeUnknownSync(TenantId)("tenant-1"),
  cpf: Schema.decodeUnknownSync(Cpf)("52998224725"),
  password: Redacted.make("correct-horse-battery-staple"),
  totpSeed: Schema.decodeUnknownSync(TotpSeed)("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
})

const configLayer = Layer.succeed(
  BrowserServiceConfig,
  BrowserServiceConfig.of({
    baseUrl: "https://browser.internal",
    authToken: Redacted.make("shared-secret"),
    timeoutMillis: 60_000
  })
)

const withReply = (reply: { status: number; body: string }) =>
  Effect.gen(function*() {
    const sent = yield* Ref.make<
      ReadonlyArray<{ url: string; body: string; auth: string | undefined }>
    >([])

    const httpLayer = Layer.succeed(
      HttpClient.HttpClient,
      HttpClient.make((request) =>
        Effect.gen(function*() {
          const body = request.body._tag === "Uint8Array"
            ? new TextDecoder().decode(request.body.body)
            : ""
          yield* Ref.update(sent, (all) => [
            ...all,
            { url: request.url, body, auth: request.headers["authorization"] }
          ])
          return HttpClientResponse.fromWeb(
            request,
            new Response(reply.body, { status: reply.status })
          )
        })
      )
    )

    const result = yield* Effect.result(
      Effect.gen(function*() {
        const browser = yield* BrowserLogin
        return yield* browser.login(credential)
      }).pipe(
        Effect.provide(
          ContainerBrowserLogin.layer.pipe(
            Layer.provide(Layer.mergeAll(httpLayer, configLayer))
          )
        )
      )
    )

    return { result, sent: yield* Ref.get(sent) } as const
  })

describe("ContainerBrowserLogin", () => {
  it.effect("posts the credential and returns the minted token", () =>
    Effect.gen(function*() {
      const { result, sent } = yield* withReply({
        status: 200,
        body: JSON.stringify({
          _tag: "Success",
          accessToken: "browser-token",
          refreshToken: "browser-refresh",
          expiresAt: 9_999_999_999_999
        })
      })

      assert.isTrue(result._tag === "Success")
      if (result._tag !== "Success") return
      assert.strictEqual(Redacted.value(result.success.accessToken), "browser-token")

      // The container is inside the trust boundary but still authenticates.
      assert.strictEqual(sent[0]?.auth, "Bearer shared-secret")
      assert.include(sent[0]?.url ?? "", "/login")
      assert.include(sent[0]?.body ?? "", "52998224725")
    }))

  it.effect("maps a rejected password to the terminal domain error", () =>
    Effect.gen(function*() {
      const { result } = yield* withReply({
        status: 200,
        body: JSON.stringify({ _tag: "InvalidPassword", detail: "senha inválida" })
      })

      assert.isTrue(result._tag === "Failure")
      if (result._tag !== "Failure") return
      // Must not be reported as transient, or the broker would keep trying.
      assert.strictEqual(result.failure._tag, "InvalidPassword")
    }))

  it.effect("keeps a rejected OTP distinct from a rejected password", () =>
    Effect.gen(function*() {
      const { result } = yield* withReply({
        status: 200,
        body: JSON.stringify({ _tag: "InvalidTotp", detail: "código inválido" })
      })

      assert.isTrue(result._tag === "Failure")
      if (result._tag !== "Failure") return
      assert.strictEqual(result.failure._tag, "InvalidTotp")
    }))

  it.effect("treats a container-side failure as transient", () =>
    Effect.gen(function*() {
      const { result } = yield* withReply({
        status: 200,
        body: JSON.stringify({ _tag: "Failed", detail: "browser crashed" })
      })

      assert.isTrue(result._tag === "Failure")
      if (result._tag !== "Failure") return
      assert.strictEqual(result.failure._tag, "SsoUnavailable")
    }))

  it.effect("treats a container 5xx as transient", () =>
    Effect.gen(function*() {
      const { result } = yield* withReply({ status: 502, body: "bad gateway" })

      assert.isTrue(result._tag === "Failure")
      if (result._tag !== "Failure") return
      assert.strictEqual(result.failure._tag, "SsoUnavailable")
    }))

  it.effect("treats an unreadable reply as transient rather than crashing", () =>
    Effect.gen(function*() {
      const { result } = yield* withReply({ status: 200, body: "{\"_tag\":\"Nonsense\"}" })

      assert.isTrue(result._tag === "Failure")
      if (result._tag !== "Failure") return
      assert.strictEqual(result.failure._tag, "SsoUnavailable")
    }))

  it.effect("attempts exactly once, leaving retry policy to the breaker", () =>
    Effect.gen(function*() {
      const { sent } = yield* withReply({
        status: 200,
        body: JSON.stringify({ _tag: "Failed", detail: "browser crashed" })
      })

      // Retrying here would multiply attempts against the SSO behind the
      // circuit breaker's back.
      assert.strictEqual(sent.length, 1)
    }))
})
