import * as Alchemy from "alchemy"
import * as Cloudflare from "alchemy/Cloudflare"
import { Effect } from "effect"
import Broker from "./src/worker.ts"
import { Database, TokenCacheNamespace } from "./src/infra/resources.ts"

/**
 * The PDPJ token broker stack.
 *
 * Infrastructure and application are one Effect program: binding a resource
 * in `src/worker.ts` is what provisions it, wires the environment variable,
 * and hands the Worker a typed client — there is no second place where the
 * two descriptions can drift apart.
 */
export default Alchemy.Stack(
  "PdpjTokenBroker",
  {
    providers: Cloudflare.providers(),
    /**
     * Remote state, shared by every deploy.
     *
     * Local state keeps the record of what exists in `.alchemy/` on whoever
     * ran the deploy. Two people — or a laptop and CI — then diff against
     * different pictures of reality, and the second deploy either recreates
     * resources the first already made or deletes ones it cannot see. A shared
     * store is what makes "who deploys" stop mattering.
     *
     * Backed by a Worker with a Durable Object and embedded SQLite, with the
     * auth token and encryption key held in the account's Secrets Store. The
     * first run against a new account prompts to bootstrap those; afterwards
     * every stack and stage on the account reuses them.
     */
    state: Cloudflare.state()
  },
  Effect.gen(function*() {
    const db = yield* Database
    const cache = yield* TokenCacheNamespace

    const broker = yield* Broker

    return {
      url: broker.url.as<string>(),
      databaseName: db.databaseName,
      cacheTitle: cache.title
    }
  })
)
