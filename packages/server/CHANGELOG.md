# Changelog

All notable changes to `@flametrench/server` are recorded here.
Spec-level changes live in [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

## [v0.0.2] — 2026-05-01

### Fixed (release-process)
- Republish to repoint transitive deps from RC versions (`@flametrench/{authz,identity,tenancy}@0.2.0-rc.{3,4,3}`) to stable (`workspace:*` resolves to `^0.2.1` at publish time). The previous `v0.0.1` was published before the v0.2.0 stable cut, locking consumers to RC builds — adopters who tried to install both `@flametrench/server` and a stable SDK got two side-by-side copies, and `IdentityStore` instances from one failed structural type-checks against the other.
- Added a `prepack` script (`pnpm build`) so future publishes always rebuild fresh `dist/` before tarballing. The previous publish flow had no rebuild guard; v0.0.1 inherited this gap from the data-layer packages.

## [v0.0.1] — 2026-04-30

Initial release. Fastify 5 reference HTTP server for Flametrench v0.1
exposing the OpenAPI surface, backed by pluggable stores.
