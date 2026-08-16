# SSO fixtures

`login-page.html` is a **real, unmodified** response captured from
`https://sso.cloud.pje.jus.br/auth/realms/pje/protocol/openid-connect/auth`
on 2026-08-16 (client `portalexterno-frontend`). It is the ground truth for
the field names and form-action shape the adapter scrapes.

The remaining fixtures are **constructed** from Keycloak's stock templates,
because producing them for real requires valid PDPJ credentials and, for the
rejection pages, deliberately failing logins against a live account — which
spends that account's lockout budget. They are marked as such rather than
passed off as recordings.

If you ever capture the genuine OTP or error pages, replace these and re-run
the suite: any drift in Keycloak's markup should surface as a test failure,
which is the point of keeping them on disk instead of inline in the test.
