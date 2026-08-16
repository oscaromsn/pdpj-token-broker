import { Effect, Layer, Redacted, Schema } from "effect"
import { FetchHttpClient, HttpClient, HttpClientRequest } from "effect/unstable/http"
import { KeycloakSso, layerHttp, SsoConfig } from "../src/adapters/sso/KeycloakSso.ts"
import { OtplibTotp } from "../src/adapters/sso/OtplibTotp.ts"
import { Cpf } from "../src/domain/Cpf.ts"
import { Credential, CredentialId, TenantId } from "../src/domain/Model.ts"
import { TotpSeed } from "../src/domain/TotpSeed.ts"
import { SsoClient } from "../src/ports/SsoClient.ts"

/**
 * End-to-end check against the real PDPJ.
 *
 * Two modes, because the two things that can be wrong fail very differently
 * and conflating them wastes an afternoon:
 *
 *   --direct   Skip the broker entirely. Log in from this process and query
 *              PDPJ. Answers "is this credential usable at all?" — no deploy,
 *              no database, no API key.
 *
 *   (default)  Go through a deployed broker: enroll, mint, query. Answers
 *              "does the service work?", and is only worth running once
 *              --direct passes.
 *
 * Usage:
 *   PDPJ_CPF=... PDPJ_PASSWORD=... PDPJ_TOTP_SEED=... \
 *     bun scripts/e2e.ts --direct [--processo 0801429-56.2022.4.05.8201]
 *
 *   PDPJ_CPF=... PDPJ_PASSWORD=... PDPJ_TOTP_SEED=... \
 *     bun scripts/e2e.ts --broker https://broker.example.workers.dev \
 *                        --key pdpj_... [--processo ...]
 *
 * This performs a REAL login against a REAL account. It makes at most one
 * login attempt and never retries: repeated failures are what lock an account
 * at the SSO, and a diagnostic tool that costs you your credential is worse
 * than no diagnostic at all.
 */

const PDPJ_REALM = "https://sso.cloud.pje.jus.br/auth/realms/pje/protocol/openid-connect"
const PDPJ_API = "https://portaldeservicos.pdpj.jus.br/api/v2/processos"

/** The process this project was originally built to reach. */
const DEFAULT_PROCESSO = "0801429-56.2022.4.05.8201"

const flag = (name: string): string | undefined => {
  const index = process.argv.indexOf(`--${name}`)
  return index === -1 ? undefined : process.argv[index + 1]
}
const has = (name: string): boolean => process.argv.includes(`--${name}`)

let step = 0
const begin = (what: string) => {
  step += 1
  process.stderr.write(`\n[${step}] ${what}\n`)
}
const ok = (detail: string) => process.stderr.write(`    ok — ${detail}\n`)
const bad = (detail: string) => process.stderr.write(`    FAILED — ${detail}\n`)
const hint = (detail: string) => process.stderr.write(`    → ${detail}\n`)

const die = (message: string): never => {
  process.stderr.write(`\nerror: ${message}\n`)
  process.exit(1)
}

const env = (name: string): string =>
  process.env[name] ?? die(`${name} is required`)

/* ────────────────────────────────────────────────────────────── shared step */

/**
 * Query PDPJ with a token. This is the only step that proves the token is
 * actually good for anything — minting a well-formed JWT says nothing about
 * whether PDPJ will honour it.
 */
const queryPdpj = Effect.fn("e2e.queryPdpj")(function*(
  accessToken: string,
  processo: string
) {
  const digits = processo.replace(/\D/g, "")
  begin(`Query PDPJ for ${processo}`)

  const client = yield* HttpClient.HttpClient
  const response = yield* client.execute(
    HttpClientRequest.get(`${PDPJ_API}/${digits}`).pipe(
      HttpClientRequest.bearerToken(accessToken),
      HttpClientRequest.acceptJson
    )
  ).pipe(Effect.catch((cause) => Effect.succeed({ status: 0, cause } as const)))

  if ("cause" in response) {
    bad(`could not reach PDPJ: ${String(response.cause)}`)
    return false
  }

  const body = yield* response.text.pipe(Effect.orElseSucceed(() => ""))

  switch (response.status) {
    case 200: {
      ok("PDPJ returned the process")
      process.stderr.write("\n")
      process.stdout.write(body.slice(0, 4000))
      process.stdout.write("\n")
      return true
    }
    case 401:
      bad("PDPJ rejected the token (401)")
      hint("the token minted but is not accepted — check the SSO client id and scope")
      return false
    case 403:
      bad("PDPJ accepted the token but refused the process (403)")
      hint(
        "the credential is valid; it simply has no standing in this case. " +
          "A sealed process is only visible to a party or counsel of record."
      )
      return false
    case 404:
      bad("PDPJ has no such process for this account (404)")
      hint(
        "expected for a process under segredo de justiça when the account is " +
          "not a party. Try a process this account is actually in, to " +
          "separate 'no access' from 'broker broken'."
      )
      return false
    default:
      bad(`PDPJ returned ${response.status}`)
      hint(body.slice(0, 300))
      return false
  }
})

/* ─────────────────────────────────────────────────────────────── direct mode */

const directMode = Effect.fn("e2e.direct")(function*(processo: string) {
  process.stderr.write("mode: direct (no broker; logs in from this process)\n")

  begin("Parse the credential")

  // Validated here, before anything touches the network. A malformed CPF or an
  // unusable seed must never turn into a login attempt — a rejected attempt
  // costs lockout budget, and this one would be entirely self-inflicted.
  const cpfResult = yield* Effect.result(Schema.decodeUnknownEffect(Cpf)(env("PDPJ_CPF")))
  if (cpfResult._tag === "Failure") {
    bad("PDPJ_CPF is not a valid CPF")
    hint("eleven digits with correct check digits; punctuation is fine")
    return false
  }
  const cpf = cpfResult.success

  const rawSeed = process.env["PDPJ_TOTP_SEED"]
  let seed: TotpSeed | undefined
  if (rawSeed !== undefined && rawSeed.length > 0) {
    const seedResult = yield* Effect.result(Schema.decodeUnknownEffect(TotpSeed)(rawSeed))
    if (seedResult._tag === "Failure") {
      bad("PDPJ_TOTP_SEED is not a usable base32 seed")
      hint("at least 26 base32 characters — the QR-code secret, not a 6-digit code")
      return false
    }
    seed = seedResult.success
  }
  ok(seed === undefined ? "CPF valid; no TOTP seed given" : "CPF and TOTP seed valid")

  const credential = new Credential({
    id: Schema.decodeUnknownSync(CredentialId)("e2e"),
    tenantId: Schema.decodeUnknownSync(TenantId)("e2e"),
    cpf,
    password: Redacted.make(env("PDPJ_PASSWORD")),
    ...(seed === undefined ? {} : { totpSeed: seed })
  })

  begin("Log in to the PDPJ SSO (one attempt, no retry)")
  const sso = yield* SsoClient
  const result = yield* Effect.result(sso.login(credential))

  if (result._tag === "Failure") {
    const error = result.failure
    bad(`${error._tag}: ${"detail" in error ? error.detail : ""}`)
    switch (error._tag) {
      case "InvalidPassword":
        hint("the account exists but the password was refused — do NOT retry")
        hint("confirm the password by signing in manually at portaldeservicos.pdpj.jus.br")
        break
      case "InvalidTotp":
        hint("password accepted, second factor refused")
        hint("check the seed matches the enrolled authenticator, and the system clock")
        break
      case "ChallengeRequired":
        hint("the SSO presented a captcha — this is what the browser container is for")
        break
      default:
        hint("transient or unexpected; the SSO may be down or the login page may have changed")
    }
    return false
  }

  const token = Redacted.value(result.success.accessToken)
  ok(`minted a token (${token.split(".").length === 3 ? "JWT" : "opaque"}, ${token.length} chars)`)

  return yield* queryPdpj(token, processo)
})

/* ─────────────────────────────────────────────────────────────── broker mode */

const CredentialViewWire = Schema.Struct({
  id: Schema.String,
  status: Schema.String,
  cpfMasked: Schema.String,
  hasTotp: Schema.Boolean,
  label: Schema.String
})
const IssuedTokenWire = Schema.Struct({
  accessToken: Schema.String,
  expiresAt: Schema.Number
})

const brokerMode = Effect.fn("e2e.broker")(function*(
  brokerUrl: string,
  apiKey: string,
  processo: string
) {
  process.stderr.write(`mode: broker (${brokerUrl})\n`)
  const client = yield* HttpClient.HttpClient
  const base = brokerUrl.replace(/\/+$/, "")

  const call = (
    request: HttpClientRequest.HttpClientRequest
  ) =>
    client.execute(HttpClientRequest.bearerToken(request, apiKey)).pipe(
      Effect.flatMap((response) =>
        response.text.pipe(
          Effect.orElseSucceed(() => ""),
          Effect.map((body) => ({ status: response.status, body }))
        )
      ),
      Effect.catch((cause) => Effect.succeed({ status: 0, body: String(cause) }))
    )

  begin("Reach the broker")
  const health = yield* client.get(`${base}/health`).pipe(
    Effect.map((r) => r.status),
    Effect.catch(() => Effect.succeed(0))
  )
  if (health !== 200) {
    bad(`/health returned ${health === 0 ? "no response" : health}`)
    hint("is the URL right, and has the stack been deployed?")
    return false
  }
  ok("/health is 200")

  begin("Authenticate with the API key")
  const listed = yield* call(HttpClientRequest.get(`${base}/credentials`))
  if (listed.status === 401) {
    bad("the broker rejected the API key (401)")
    hint("mint one with: bun run keys mint --tenant <t> --label e2e ...")
    return false
  }
  if (listed.status !== 200) {
    bad(`/credentials returned ${listed.status}: ${listed.body.slice(0, 200)}`)
    return false
  }
  ok("API key accepted")

  // Reuse an existing e2e credential rather than piling up a new row on every
  // run — there is no delete endpoint, deliberately.
  const existing = yield* Schema.decodeUnknownEffect(Schema.Array(CredentialViewWire))(
    JSON.parse(listed.body) as unknown
  ).pipe(Effect.orElseSucceed(() => [] as ReadonlyArray<typeof CredentialViewWire.Type>))
  const reusable = existing.find((view) => view.label === "e2e")

  let credentialId: string
  if (reusable !== undefined) {
    begin("Reuse the existing e2e credential")
    ok(`${reusable.id} (${reusable.cpfMasked}, status ${reusable.status})`)
    credentialId = reusable.id
  } else {
    begin("Enroll the credential")
    const seed = process.env["PDPJ_TOTP_SEED"]
    const enrolled = yield* call(
      HttpClientRequest.post(`${base}/credentials`).pipe(
        HttpClientRequest.bodyJsonUnsafe({
          label: "e2e",
          cpf: env("PDPJ_CPF"),
          password: env("PDPJ_PASSWORD"),
          ...(seed === undefined || seed.length === 0 ? {} : { totpSeed: seed })
        })
      )
    )
    if (enrolled.status === 400) {
      bad("the broker rejected the credential payload (400)")
      hint("usually an invalid CPF or a TOTP seed under 26 base32 characters")
      hint(enrolled.body.slice(0, 300))
      return false
    }
    if (enrolled.status !== 200) {
      bad(`enroll returned ${enrolled.status}: ${enrolled.body.slice(0, 200)}`)
      return false
    }
    const view = yield* Schema.decodeUnknownEffect(CredentialViewWire)(
      JSON.parse(enrolled.body) as unknown
    ).pipe(Effect.orDie)
    ok(`${view.id} (${view.cpfMasked}, hasTotp=${view.hasTotp}, status ${view.status})`)
    credentialId = view.id
  }

  begin("Ask the broker for a token")
  const issued = yield* call(HttpClientRequest.post(`${base}/credentials/${credentialId}/token`))

  if (issued.status !== 200) {
    bad(`token endpoint returned ${issued.status}`)
    switch (issued.status) {
      case 422:
        hint("the stored credential was refused by the SSO — password or seed is wrong")
        hint("fix it at the source, then re-enroll; the broker will not retry a bad credential")
        break
      case 429:
        hint("the circuit breaker is open after repeated failures — wait out the cooldown")
        break
      case 502:
        hint("the SSO itself failed or is unreachable; this one is transient")
        break
      case 404:
        hint("no such credential for this tenant")
        break
      default:
        hint(issued.body.slice(0, 300))
    }
    return false
  }

  const token = yield* Schema.decodeUnknownEffect(IssuedTokenWire)(
    JSON.parse(issued.body) as unknown
  ).pipe(Effect.orDie)
  const secondsLeft = Math.round((token.expiresAt - Date.now()) / 1000)
  ok(`token issued, valid for ~${secondsLeft}s`)

  return yield* queryPdpj(token.accessToken, processo)
})

/* ───────────────────────────────────────────────────────────────────── main */

const processo = flag("processo") ?? DEFAULT_PROCESSO

process.stderr.write(
  "This performs a REAL login against a REAL account.\n" +
    "One attempt, no retries — repeated failures lock an account at the SSO.\n"
)

const program = (has("direct")
  ? directMode(processo)
  : brokerMode(
    flag("broker") ?? die("--broker <url> is required (or pass --direct)"),
    flag("key") ?? die("--key <api-key> is required (or pass --direct)"),
    processo
  )
).pipe(
  Effect.provide(
    Layer.mergeAll(
      layerHttp,
      FetchHttpClient.layer,
      KeycloakSso.layer.pipe(
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
    )
  )
)

Effect.runPromise(program)
  .then((passed) => {
    process.stderr.write(passed ? "\nPASS\n" : "\nFAIL — see the hints above\n")
    process.exit(passed ? 0 : 1)
  })
  .catch((error: unknown) => {
    process.stderr.write(`\nunexpected: ${String(error)}\n`)
    process.exit(1)
  })
