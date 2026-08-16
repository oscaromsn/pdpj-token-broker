import { Schema } from "effect"
import * as SchemaGetter from "effect/SchemaGetter"

/**
 * Modulo-11 check digit over the first `upTo` digits, per Receita Federal's
 * CPF algorithm. Weights count down from `upTo + 1`.
 */
const checkDigit = (digits: string, upTo: number): number => {
  let sum = 0
  for (let i = 0; i < upTo; i++) {
    // Safe: caller only passes `upTo` <= digits.length, and `digits` is
    // already known to be 11 ASCII numerals.
    sum += Number(digits[i]) * (upTo + 1 - i)
  }
  const remainder = (sum * 10) % 11
  return remainder === 10 ? 0 : remainder
}

const hasValidCheckDigits = (digits: string): boolean =>
  checkDigit(digits, 9) === Number(digits[9]) &&
  checkDigit(digits, 10) === Number(digits[10])

/**
 * Eleven identical digits satisfy the modulo-11 checksum but are never issued.
 * Without this guard "00000000000" would validate.
 */
const isRepeatedDigit = (digits: string): boolean => /^(\d)\1{10}$/.test(digits)

/**
 * A Brazilian CPF, normalized to eleven digits with the check digits verified.
 *
 * Punctuation is stripped on the way in so that "529.982.247-25" and
 * "52998224725" are the same value — the SSO only ever sees the bare digits.
 *
 * Validation messages deliberately omit the offending value: a CPF is personal
 * data under the LGPD and error payloads reach logs and traces.
 */
export const Cpf = Schema.String.pipe(
  Schema.decodeTo(Schema.String, {
    decode: SchemaGetter.transform((raw: string) => raw.replace(/\D/g, "")),
    encode: SchemaGetter.passthrough()
  }),
  Schema.check(
    Schema.makeFilter((digits: string) =>
      digits.length === 11 && !isRepeatedDigit(digits) && hasValidCheckDigits(digits)
        ? undefined
        : "must be 11 digits with valid check digits"
    )
  ),
  Schema.brand("Cpf")
)

export type Cpf = typeof Cpf.Type
