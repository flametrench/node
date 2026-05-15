# Changelog

All notable changes to `@flametrench/server` are recorded here.
Spec-level changes live in [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

## [v0.0.3] — 2026-05-15

### Added (bearer prefix dispatch, ADR 0016)
- New `resolveBearer(token, { identityStore, shareStore? })` helper for routing incoming bearer tokens to the matching verifier. Implements the prefix-routing contract from ADR 0016: `pat_<32hex>_<…>` → `verifyPatToken`, `shr_<…>` → `verifyShareToken`, anything else → `verifySessionToken`. Returns a discriminated union with the `kind` field aligned to the `auth.kind` audit discriminator (`"session" | "pat" | "share"`).
- New `TokenFormatUnrecognizedError` (code `auth.token_format_unrecognized`) for `shr_…` bearers presented when no shareStore is wired.
- 8 new tests covering routing, error propagation, and the no-cross-route invariant.

## [v0.0.2] — 2026-05-01

### Fixed (release-process)
- Republish to repoint transitive deps from RC versions (`@flametrench/{authz,identity,tenancy}@0.2.0-rc.{3,4,3}`) to stable (`workspace:*` resolves to `^0.2.1` at publish time). The previous `v0.0.1` was published before the v0.2.0 stable cut, locking consumers to RC builds — adopters who tried to install both `@flametrench/server` and a stable SDK got two side-by-side copies, and `IdentityStore` instances from one failed structural type-checks against the other.
- Added a `prepack` script (`pnpm build`) so future publishes always rebuild fresh `dist/` before tarballing. The previous publish flow had no rebuild guard; v0.0.1 inherited this gap from the data-layer packages.

## [v0.0.1] — 2026-04-30

Initial release. Fastify 5 reference HTTP server for Flametrench v0.1
exposing the OpenAPI surface, backed by pluggable stores.
