import { Effect, Schema } from "effect"
import type { Browser, Page, Request as PwRequest } from "playwright-core"
import { generateSync } from "otplib"
import { TOTP_PERIOD_MILLIS } from "../sso/OtplibTotp.ts"
import { BrowserLoginRequest, type BrowserLoginReply } from "./Protocol.ts"

/**
 * The container half of the browser fallback: drives a real Chromium through
 * the PDPJ login and captures the resulting token.
 *
 * This exists for exactly one situation — the HTTP transport hit a captcha or
 * a JS wall and reported `ChallengeRequired`. It is slow and expensive, which
 * is why it is the last rung of the cascade rather than the default.
 *
 * ## Verification status
 *
 * The logic here is ported from `PJePA`'s `pje_client._login`, which runs
 * against live tribunal PJe instances, and the selectors match the real login
 * page captured in `test/sso/fixtures/login-page.html`. But unlike every other
 * module in this project it is **not covered by the test suite**: asserting on
 * it requires a real Chromium and a real account, and the failure paths would
 * mean deliberately failing logins against that account. Treat it as unproven
 * until it has been exercised against the live SSO.
 */

/** Matches the real page: `input#username`, `input#password`, `input#kc-login`. */
const USERNAME = "input#username"
const PASSWORD = "input#password"
const SUBMIT = "input#kc-login, button[type='submit']"
const OTP = "input#otp, input[name='otp']"

/** Keycloak renders rejections into these. */
const ERROR_TEXT = ".kc-feedback-text, .pf-c-alert__title, #input-error"

const PORTAL_ORIGIN = "https://portaldeservicos.pdpj.jus.br"

export class PlaywrightUnavailable extends Schema.TaggedError<PlaywrightUnavailable>()(
  "PlaywrightUnavailable",
  { detail: Schema.String }
) {}

const textOf = (page: Page, selector: string): Promise<string> =>
  page
    .locator(selector)
    .first()
    .innerText({ timeout: 1_000 })
    .catch(() => "")

/**
 * Generate a TOTP code, waiting out a window that is about to close.
 *
 * Duplicated from `OtplibTotp` rather than shared because this half runs in a
 * different process with no Effect `Clock` to inject; the three-second floor
 * is the same and must stay in step.
 */
const totpCode = (seed: string): string => {
  const remaining = TOTP_PERIOD_MILLIS - (Date.now() % TOTP_PERIOD_MILLIS)
  if (remaining < 3_000) {
    const start = Date.now()
    // Deliberately blocking: this runs in a single-purpose container whose
    // only job is this login, so there is nothing else to starve.
    while (Date.now() - start < remaining) { /* wait out the window */ }
  }
  return generateSync({
    secret: seed,
    strategy: "totp",
    epoch: Math.floor(Date.now() / 1000),
    period: TOTP_PERIOD_MILLIS / 1000
  })
}

/**
 * Run one login in a fresh, isolated browser context.
 *
 * A fresh context per attempt is the same requirement as the per-attempt
 * cookie jar on the HTTP path: a reused profile would carry one tenant's
 * session into another tenant's login.
 */
export const login = Effect.fn("PlaywrightLogin.login")(
  function*(browser: Browser, request: BrowserLoginRequest) {
    const reply = yield* Effect.tryPromise({
      try: async (): Promise<BrowserLoginReply> => {
        const context = await browser.newContext({ ignoreHTTPSErrors: false })
        try {
          const page = await context.newPage()

          // The token never appears in the DOM — it is an `Authorization`
          // header on the portal's own XHRs. Watching requests is the only
          // way to see it, and is what `microservico-pdpj` does.
          let captured: string | undefined
          page.on("request", (pwRequest: PwRequest) => {
            if (captured !== undefined) return
            const header = pwRequest.headers()["authorization"]
            if (header?.startsWith("Bearer ") === true) {
              captured = header.slice("Bearer ".length)
            }
          })

          await page.goto(`${PORTAL_ORIGIN}/consulta`, { waitUntil: "domcontentloaded" })

          await page.waitForSelector(USERNAME, { timeout: 20_000 })
          await page.fill(USERNAME, request.cpf)
          await page.fill(PASSWORD, request.password)
          await page.click(SUBMIT)
          await page.waitForLoadState("domcontentloaded")

          // Either a second factor is demanded, or the password was refused,
          // or we are already through. Decide on positive evidence only.
          const needsOtp = await page
            .locator(OTP)
            .first()
            .isVisible({ timeout: 8_000 })
            .catch(() => false)

          if (needsOtp) {
            if (request.totpSeed === undefined) {
              return {
                _tag: "InvalidTotp",
                detail: "SSO asked for a second factor but no seed is enrolled"
              }
            }
            await page.fill(OTP, totpCode(request.totpSeed))
            await page.click(SUBMIT)
            await page.waitForLoadState("domcontentloaded")
          }

          const stillOnPassword = await page
            .locator(PASSWORD)
            .first()
            .isVisible({ timeout: 2_000 })
            .catch(() => false)
          if (stillOnPassword) {
            return { _tag: "InvalidPassword", detail: await textOf(page, ERROR_TEXT) }
          }

          const stillOnOtp = await page
            .locator(OTP)
            .first()
            .isVisible({ timeout: 2_000 })
            .catch(() => false)
          if (stillOnOtp) {
            return { _tag: "InvalidTotp", detail: await textOf(page, ERROR_TEXT) }
          }

          // Provoke the portal into calling its own API so the header appears.
          await page.evaluate(() => {
            void fetch("/api/v2/processos?numeroProcesso=00000000000000000000", {
              credentials: "include"
            })
          })

          const deadline = Date.now() + 20_000
          while (captured === undefined && Date.now() < deadline) {
            await page.waitForTimeout(250)
          }

          if (captured === undefined) {
            return { _tag: "Failed", detail: "logged in but no bearer token was observed" }
          }

          return {
            _tag: "Success",
            accessToken: captured,
            // A token scraped from a header carries no `expires_in`. Claiming
            // a long life would let the cache serve a dead token; five
            // minutes is short enough to be safe and long enough to be useful.
            expiresAt: Date.now() + 5 * 60_000
          }
        } finally {
          await context.close()
        }
      },
      catch: (cause) =>
        new PlaywrightUnavailable({ detail: `browser login failed: ${String(cause)}` })
    })

    return reply
  }
)

export { BrowserLoginRequest }
