import { Schema } from "effect"
import * as SchemaGetter from "effect/SchemaGetter"

/**
 * A CNJ process number, normalized to its twenty digits.
 *
 * Punctuation is stripped so "0801429-56.2022.4.05.8201" and its bare-digit
 * form are one value; the PDPJ API is queried by the bare digits. The check
 * digit is not re-validated here — the API is the authority on whether a
 * number exists — but the length is, so a truncated paste fails at the edge
 * rather than as a puzzling 404.
 */
export const ProcessNumber = Schema.String.pipe(
  Schema.decodeTo(Schema.String, {
    decode: SchemaGetter.transform((raw: string) => raw.replace(/\D/g, "")),
    encode: SchemaGetter.passthrough()
  }),
  Schema.check(
    Schema.makeFilter((digits: string) =>
      digits.length === 20 ? undefined : "a CNJ process number has 20 digits"
    )
  ),
  Schema.brand("ProcessNumber")
)

export type ProcessNumber = typeof ProcessNumber.Type
