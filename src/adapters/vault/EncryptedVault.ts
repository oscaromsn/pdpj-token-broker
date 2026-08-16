import { Effect, Layer, Option, Redacted, Schema } from "effect"
import { Envelope } from "../../crypto/Envelope.ts"
import { Cpf } from "../../domain/Cpf.ts"
import { CredentialNotFound, VaultCorrupt, VaultUnavailable } from "../../domain/Errors.ts"
import {
  Credential,
  CredentialId,
  CredentialView,
  maskCpf,
  type CredentialStatus,
  type TenantId
} from "../../domain/Model.ts"
import { TotpSeed } from "../../domain/TotpSeed.ts"
import { CredentialRow, CredentialStore } from "../../ports/CredentialStore.ts"
import { CredentialVault } from "../../ports/CredentialVault.ts"
import { KeyRing } from "../../ports/KeyRing.ts"

/**
 * The secrets, as they exist inside the sealed blob.
 *
 * Encoded as plain strings rather than the `Redacted` domain types: this
 * shape is only ever produced immediately before sealing and consumed
 * immediately after opening, and `Redacted` deliberately refuses to encode.
 * Keeping the wire shape separate from the domain shape is what lets the
 * domain forbid serialization while the vault can still persist.
 */
const SecretPayload = Schema.Struct({
  cpf: Schema.String,
  password: Schema.String,
  totpSeed: Schema.optional(Schema.String)
})

const encodePayload = Schema.encodeSync(Schema.fromJsonString(SecretPayload))
const decodePayload = Schema.decodeUnknownSync(Schema.fromJsonString(SecretPayload))

const decodeCpf = Schema.decodeUnknownEffect(Cpf)
const decodeSeed = Schema.decodeUnknownEffect(TotpSeed)

/**
 * `CredentialVault` implemented as envelope encryption over a row store.
 *
 * Two ports underneath, deliberately: `KeyRing` supplies a per-tenant data
 * key and `CredentialStore` persists opaque rows. Neither knows about the
 * other, which is what makes "the database alone is worthless" a structural
 * property rather than a policy — the store literally never sees a key.
 *
 * The read path is the interesting asymmetry. `get` unseals and therefore
 * needs a key; `list` answers entirely from the plaintext management columns
 * and never asks for one. A caller that only enumerates credentials cannot
 * leak a secret even if the key service is wide open, because it never
 * requests a key at all.
 */
export class EncryptedVault {
  static readonly layer: Layer.Layer<CredentialVault, never, CredentialStore | KeyRing> =
    Layer.effect(
      CredentialVault,
      Effect.gen(function*() {
        const store = yield* CredentialStore
        const keyring = yield* KeyRing

        const viewOf = (row: CredentialRow): CredentialView =>
          new CredentialView({
            id: row.id,
            tenantId: row.tenantId,
            label: row.label,
            cpfMasked: row.cpfMasked,
            hasTotp: row.hasTotp,
            status: row.status,
            ...(row.lastLoginAt === undefined ? {} : { lastLoginAt: row.lastLoginAt }),
            ...(row.lastError === undefined ? {} : { lastError: row.lastError })
          })

        const get = Effect.fn("EncryptedVault.get")(
          function*(tenantId: TenantId, id: CredentialId) {
            const row = yield* store.find(tenantId, id).pipe(
              Effect.mapError((cause) =>
                new VaultUnavailable({ detail: cause.detail, cause })
              )
            )

            // A row belonging to another tenant is reported as absent rather
            // than forbidden: "exists but not yours" is itself a disclosure.
            if (Option.isNone(row)) {
              return yield* new CredentialNotFound({ credentialId: id })
            }

            const key = yield* keyring.dekFor(tenantId).pipe(
              Effect.mapError((cause) =>
                new VaultUnavailable({ detail: cause.detail, cause })
              )
            )

            const json = yield* Envelope.open(key, row.value.sealed).pipe(
              // A failed open is either a wrong key or a modified ciphertext,
              // and GCM cannot tell us which. Both mean the same thing to an
              // operator: this row can no longer be trusted.
              Effect.mapError(() =>
                new VaultCorrupt({
                  credentialId: id,
                  detail: "sealed payload failed authentication"
                })
              )
            )

            const payload = yield* Effect.try({
              try: () => decodePayload(json),
              catch: () =>
                new VaultCorrupt({ credentialId: id, detail: "sealed payload is malformed" })
            })

            const cpf = yield* decodeCpf(payload.cpf).pipe(
              Effect.mapError(() =>
                new VaultCorrupt({ credentialId: id, detail: "stored CPF is invalid" })
              )
            )

            const seed = payload.totpSeed === undefined
              ? undefined
              : yield* decodeSeed(payload.totpSeed).pipe(
                Effect.mapError(() =>
                  new VaultCorrupt({ credentialId: id, detail: "stored TOTP seed is invalid" })
                )
              )

            return new Credential({
              id: row.value.id,
              tenantId: row.value.tenantId,
              cpf,
              password: Redacted.make(payload.password),
              ...(seed === undefined ? {} : { totpSeed: seed })
            })
          }
        )

        const list = Effect.fn("EncryptedVault.list")(function*(tenantId: TenantId) {
          const rows = yield* store.all(tenantId).pipe(
            Effect.mapError((cause) => new VaultUnavailable({ detail: cause.detail, cause }))
          )
          return rows.map(viewOf)
        })

        const put = Effect.fn("EncryptedVault.put")(
          function*(credential: Credential, label: string) {
            const key = yield* keyring.dekFor(credential.tenantId).pipe(
              Effect.mapError((cause) => new VaultUnavailable({ detail: cause.detail, cause }))
            )

            const json = encodePayload({
              cpf: credential.cpf,
              password: Redacted.value(credential.password),
              ...(credential.totpSeed === undefined
                ? {}
                : { totpSeed: Redacted.value(credential.totpSeed) })
            })

            const sealed = yield* Envelope.seal(key, json).pipe(
              Effect.mapError((cause) =>
                new VaultUnavailable({ detail: "failed to seal credential", cause })
              )
            )

            yield* store.upsert(
              new CredentialRow({
                id: credential.id,
                tenantId: credential.tenantId,
                label,
                cpfMasked: maskCpf(credential.cpf),
                hasTotp: credential.totpSeed !== undefined,
                // Never `active` on write. A credential is only trustworthy
                // once a real login has proven it, which the broker records.
                status: "validating",
                sealed
              })
            ).pipe(
              Effect.mapError((cause) => new VaultUnavailable({ detail: cause.detail, cause }))
            )

            return credential.id
          }
        )

        const setStatus = Effect.fn("EncryptedVault.setStatus")(
          function*(
            tenantId: TenantId,
            id: CredentialId,
            status: CredentialStatus,
            detail?: string
          ) {
            yield* store.patchStatus(tenantId, id, status, detail).pipe(
              Effect.mapError((cause) => new VaultUnavailable({ detail: cause.detail, cause }))
            )
          }
        )

        return CredentialVault.of({ get, list, put, setStatus })
      })
    )
}
