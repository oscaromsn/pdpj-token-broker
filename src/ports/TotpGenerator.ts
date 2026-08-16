import { Context, type Effect } from "effect"
import type { TotpSeed } from "../domain/TotpSeed.ts"

/**
 * Port: turns a seed into the six digits the SSO is asking for.
 *
 * Returns an Effect rather than a plain string because generation is
 * time-dependent and may need to *wait*: PJePA's hard-won detail is that a
 * code produced with under ~3 seconds left in its window can expire in flight
 * and be rejected. The implementation sleeps into the next window instead of
 * handing back a code that is about to die.
 */
export class TotpGenerator extends Context.Service<TotpGenerator, {
  generate(seed: TotpSeed): Effect.Effect<string>
}>()("broker/ports/TotpGenerator") {}
