/**
 * Browser-like headers for the PDPJ process API.
 *
 * `portaldeservicos.pdpj.jus.br` sits behind a WAF that rejects requests which
 * do not look like they came from the portal's own SPA. This was found the
 * hard way in a live run: the exact query that returned data from inside a
 * real browser came back `403 <html>Forbidden</html>` (a gateway block, not
 * the application's JSON 403) when issued from a plain HTTP client with no
 * `User-Agent` or `Referer`.
 *
 * The SSO token endpoint (`sso.cloud.pje.jus.br`) does *not* need these — it
 * answered a bare refresh grant fine — so they are scoped to the process API.
 *
 * A caveat worth keeping in view: some WAFs also fingerprint the TLS handshake
 * (JA3), which headers cannot disguise. If a query still gets blocked from a
 * non-browser client despite these headers, the token has to be spent from a
 * real browser context — which is the model the broker uses anyway, since the
 * token is minted from a browser session to begin with.
 */
export const PDPJ_BROWSER_HEADERS: Record<string, string> = {
  "user-agent":
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
    "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
  accept: "application/json, text/plain, */*",
  "accept-language": "pt-BR,pt;q=0.9,en;q=0.8",
  origin: "https://portaldeservicos.pdpj.jus.br",
  referer: "https://portaldeservicos.pdpj.jus.br/",
  "sec-fetch-dest": "empty",
  "sec-fetch-mode": "cors",
  "sec-fetch-site": "same-origin"
}
