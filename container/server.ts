import { NodeHttpServer, NodeRuntime } from "@effect/platform-node"
import { Config, Effect, Layer, Redacted, Schema, Semaphore } from "effect"
import {
  HttpRouter,
  HttpServer,
  HttpServerRequest,
  HttpServerResponse
} from "effect/unstable/http"
import { timingSafeEqual } from "node:crypto"
import { createServer } from "node:http"
import { chromium, type Browser } from "playwright-core"
import { login } from "../src/adapters/browser/PlaywrightLogin.ts"
import { BrowserLoginRequest, type BrowserLoginReply } from "../src/adapters/browser/Protocol.ts"

/**
 * The browser fallback service.
 *
 * Reached only when the HTTP transport reports `ChallengeRequired` — a captcha
 * or JS wall the form replay cannot answer. Everything else in the broker
 * avoids this path, because a real browser costs seconds and hundreds of
 * megabytes where an HTTP round trip costs milliseconds.
 *
 * ## Trust boundary
 *
 * This service receives plaintext CPFs, passwords and TOTP seeds. It has to —
 * something must type them into a login form — which puts it *inside* the
 * vault's trust boundary, not adjacent to it. It must never be exposed to the
 * internet, must be reached over TLS, and authenticates every request with a
 * shared token so that being merely network-adjacent is not enough to ask it
 * to log in as somebody.
 */

const decodeRequest = Schema.decodeUnknownEffect(BrowserLoginRequest)

/**
 * Concurrent logins allowed at once.
 *
 * Each one drives a browser context with a live page; a handful in parallel
 * will exhaust a small container's memory and take the whole service down
 * rather than slowing it. Queuing beyond this is the right failure mode — the
 * caller already has a 90-second timeout.
 */
const MAX_CONCURRENT_LOGINS = 3

/**
 * Compare tokens in constant time.
 *
 * `timingSafeEqual` throws on unequal lengths, which would itself leak length
 * through the error path, so the mismatch branch still performs a comparison
 * before returning.
 */
const tokenMatches = (presented: string, expected: string): boolean => {
  const encoder = new TextEncoder()
  const a = encoder.encode(presented)
  const b = encoder.encode(expected)
  if (a.length !== b.length) {
    timingSafeEqual(b, b)
    return false
  }
  return timingSafeEqual(a, b)
}

const bearerFrom = (header: string | undefined): string | undefined =>
  header?.startsWith("Bearer ") === true ? header.slice("Bearer ".length) : undefined

const failed = (detail: string): BrowserLoginReply => ({ _tag: "Failed", detail })

const RoutesLayer = HttpRouter.use((router) =>
  Effect.gen(function*() {
    const authToken = yield* Config.redacted("BROWSER_SERVICE_TOKEN")

    /**
     * One browser for the life of the process.
     *
     * Launching Chromium takes seconds; contexts are cheap. `PlaywrightLogin`
     * opens a fresh context per attempt, which is what keeps one tenant's
     * session cookies out of another tenant's login.
     */
    const browser: Browser = yield* Effect.acquireRelease(
      Effect.promise(() =>
        chromium.launch({
          args: [
            // Containers get a 64 MB /dev/shm by default, which Chromium
            // exhausts and then dies with no useful error. `--ipc=host` covers
            // this too where the runtime allows it; this covers where it does
            // not.
            "--disable-dev-shm-usage",
            // The container is the isolation boundary, and the kernel
            // namespaces Chromium's sandbox wants are unavailable inside one.
            // Running as a non-root user is the compensating control.
            "--no-sandbox",
            "--disable-gpu"
          ]
        })
      ),
      (instance) => Effect.promise(() => instance.close()).pipe(Effect.ignore)
    )

    const semaphore = yield* Semaphore.make(MAX_CONCURRENT_LOGINS)

    const handleLogin = Effect.gen(function*() {
      const request = yield* HttpServerRequest.HttpServerRequest

      const presented = bearerFrom(request.headers["authorization"])
      if (presented === undefined || !tokenMatches(presented, Redacted.value(authToken))) {
        // Deliberately terse: nothing here should help an attacker learn
        // whether a token was close.
        return HttpServerResponse.text("unauthorized", { status: 401 })
      }

      const body = yield* request.json.pipe(
        Effect.mapError(() => failed("unreadable body"))
      )
      const payload = yield* decodeRequest(body).pipe(
        Effect.mapError(() => failed("malformed body"))
      )

      const reply = yield* login(browser, payload).pipe(
        Semaphore.withPermits(semaphore, 1),
        // A browser failure is transient for the caller, not a credential
        // problem — mapping it to `Failed` keeps the broker from marking a
        // perfectly good credential as broken.
        Effect.catch((error) => Effect.succeed(failed(error.detail)))
      )

      return yield* HttpServerResponse.json(reply).pipe(Effect.orDie)
    }).pipe(
      Effect.catch((reply: BrowserLoginReply) =>
        HttpServerResponse.json(reply, { status: 400 }).pipe(Effect.orDie)
      ),
      // A defect must not take the process down: this container serves many
      // logins, and one bad page should cost one request.
      Effect.catchDefect((defect) =>
        Effect.logError("browser login defect", { defect }).pipe(
          Effect.andThen(
            HttpServerResponse.json(failed("internal browser error"), { status: 500 }).pipe(
              Effect.orDie
            )
          )
        )
      )
    )

    yield* router.add("POST", "/login", handleLogin)

    // Liveness only — unauthenticated so an orchestrator can reach it, and
    // free of any detail about the service.
    yield* router.add(
      "GET",
      "/health",
      Effect.sync(() =>
        browser.isConnected()
          ? HttpServerResponse.text("ok")
          : HttpServerResponse.text("browser down", { status: 503 })
      )
    )
  })
)

const port = Number(process.env["PORT"] ?? 8080)

const ServerLayer = HttpRouter.serve(RoutesLayer).pipe(
  Layer.provide(NodeHttpServer.layer(createServer, { port }))
)

Layer.launch(ServerLayer).pipe(NodeRuntime.runMain)
