import { Context, type Effect, type Option, Schema } from "effect"
import { Sealed } from "../crypto/Envelope.ts"
import { CredentialId, CredentialStatus, TenantId } from "../domain/Model.ts"

/**
 * A credential exactly as it sits at rest.
 *
 * Everything sensitive is inside `sealed`. The plaintext columns are only
 * what an operator needs in order to *recognize and manage* a credential:
 * a label, a masked CPF, whether a second factor is enrolled, and its health.
 * None of them help anyone use the credential.
 *
 * `hasTotp` is stored rather than derived so that `list` can answer it
 * without ever unsealing — see the note on `CredentialStore`.
 */
export class CredentialRow extends Schema.Class<CredentialRow>("broker/ports/CredentialRow")({
  id: CredentialId,
  tenantId: TenantId,
  label: Schema.String,
  cpfMasked: Schema.String,
  hasTotp: Schema.Boolean,
  status: CredentialStatus,
  sealed: Sealed,
  lastLoginAt: Schema.optional(Schema.Number),
  lastError: Schema.optional(Schema.String)
}) {}

export class StoreUnavailable extends Schema.TaggedError<StoreUnavailable>()(
  "StoreUnavailable",
  { detail: Schema.String, cause: Schema.optional(Schema.Defect()) }
) {}

/**
 * Port: durable rows. Knows about storage, knows nothing about cryptography.
 *
 * Splitting this from `CredentialVault` is what lets the encryption logic be
 * tested against an in-memory map with real AES, and lets the D1 adapter be
 * tested for persistence without touching key management. Neither half has to
 * fake the other.
 */
export class CredentialStore extends Context.Service<CredentialStore, {
  find(
    tenantId: TenantId,
    id: CredentialId
  ): Effect.Effect<Option.Option<CredentialRow>, StoreUnavailable>

  all(tenantId: TenantId): Effect.Effect<ReadonlyArray<CredentialRow>, StoreUnavailable>

  upsert(row: CredentialRow): Effect.Effect<void, StoreUnavailable>

  patchStatus(
    tenantId: TenantId,
    id: CredentialId,
    status: CredentialStatus,
    detail?: string
  ): Effect.Effect<void, StoreUnavailable>
}>()("broker/ports/CredentialStore") {}
