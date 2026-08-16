import { Context, type Effect } from "effect"
import type { CredentialNotFound, VaultCorrupt, VaultUnavailable } from "../domain/Errors.ts"
import type { Credential, CredentialId, CredentialStatus, CredentialView, TenantId } from "../domain/Model.ts"

/**
 * Port: durable, encrypted storage for tenant credentials.
 *
 * The interface names no storage engine and no cipher. That is the point of
 * the boundary — the domain is written against "somewhere I can get a
 * credential", and D1-plus-envelope-encryption is one way to be that, while
 * an in-memory `Ref` is another. Both are equally valid implementations, which
 * is what lets the whole broker cascade be tested without a database.
 *
 * Note the asymmetry: `get` returns the decrypted `Credential`, but `list`
 * returns only `CredentialView`. Callers that merely enumerate credentials
 * cannot accidentally obtain secrets, because the type they receive has
 * nowhere to put them.
 */
export class CredentialVault extends Context.Service<CredentialVault, {
  /** Decrypt and return a credential. Scoped by tenant to prevent cross-reads. */
  get(
    tenantId: TenantId,
    id: CredentialId
  ): Effect.Effect<Credential, CredentialNotFound | VaultCorrupt | VaultUnavailable>

  /** Safe metadata only — never secrets. */
  list(tenantId: TenantId): Effect.Effect<ReadonlyArray<CredentialView>, VaultUnavailable>

  /** Encrypt and store. Returns the handle callers use from then on. */
  put(credential: Credential, label: string): Effect.Effect<CredentialId, VaultUnavailable>

  /**
   * Record the outcome of a login attempt. This is what moves a credential
   * between `validating`, `active` and `error`, so the lifecycle is driven by
   * observed reality rather than by what the enroller claimed.
   */
  setStatus(
    tenantId: TenantId,
    id: CredentialId,
    status: CredentialStatus,
    detail?: string
  ): Effect.Effect<void, VaultUnavailable>
}>()("broker/ports/CredentialVault") {}
