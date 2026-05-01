# Changelog

All notable changes to `@flametrench/identity` are recorded here.
Spec-level changes live in [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

## [v0.2.1] — 2026-05-01

### Fixed (release-process)
- Republish to ship the ADR 0013 savepoint-cooperation code that has been in source since commit `ff0b826` ("ADR 0013 Node rollout") but was missing from the published `v0.2.0` tarball — the `dist/` directory tracked by `files: ["dist", ...]` was packed from a stale build. Without savepoint cooperation, `PostgresIdentityStore` constructed against a caller-owned `PoolClient` (e.g. inside an adopter's outer transaction) failed with `"Client has already been connected"` whenever a multi-statement method (e.g. `createSession`) tried to `pool.connect()`. After v0.2.1, all multi-statement methods cooperate via `SAVEPOINT`/`RELEASE` when the adapter detects it was given a `PoolClient`, falling back to `BEGIN`/`COMMIT` when given a `Pool`.
- Added a `prepack` script (`pnpm build`) so future publishes always rebuild fresh `dist/` before tarballing. The previous `prepublishOnly` only asserted pnpm was being used; it did not rebuild. Published packages will now always reflect the source they were tagged at.
- Added a regression test (`test/dist-savepoint.test.ts`) that asserts the bundled `dist/` contains the savepoint cooperation markers, so any future build that fails to compile the code path fails CI before publish.

## [v0.2.0-rc.5] — 2026-04-27

### Fixed (security posture)
- `verifyPassword` now consults `usr_mfa_policy` and returns `VerifiedCredentialResult` with `mfaRequired: true` when a user has `required = true` AND the grace window has elapsed (or was never set). Previously the policy table was decorative — the SDK never read it, so an adopter configuring per-user MFA enforcement could be bypassed by application code that called `createSession` directly without checking the policy. The new field is additive (`mfaRequired: false` by default), so adopters who do not configure a policy see no behavioral change. Applications MUST gate `createSession` on `mfaRequired` by calling `verifyMfa` first when it is `true`. (ADR 0008.)

## [v0.2.0-rc.4] — 2026-04-27

### Added
- `PostgresIdentityStore` (new export at `@flametrench/identity/postgres`) — a Postgres-backed `IdentityStore`. Mirrors `InMemoryIdentityStore` byte-for-byte at the SDK boundary; the difference is durability and concurrency.
  - Schema: `spec/reference/postgres.sql` (the `usr`, `cred`, `ses`, `mfa`, `usr_mfa_policy` tables, plus `ses.mfa_verified_at`).
  - Connection: accepts a `pg.Pool`. `pg ^8.11.0` declared as an optional peer dep — adopters using only the in-memory store don't pull it in.
  - Token storage: SHA-256 hashed and stored as 32 raw bytes (`BYTEA`). Plaintext tokens are returned ONCE on create/refresh and never persisted.
  - Multi-statement ops (`revokeUser` cascade, credential rotation, `refreshSession`, MFA confirm/verify, recovery-slot consumption) run inside a transaction.
  - Coverage: 26 integration tests, gated on `IDENTITY_POSTGRES_URL`.

## [v0.2.0-rc.3] — 2026-04-26

### Added (MFA store ops, ADR 0008 Phase 1)
- `enrollTotpFactor`, `enrollWebAuthnFactor`, `enrollRecoveryFactor`, `confirmTotpFactor`, `confirmWebAuthnFactor`, `revokeMfaFactor`, `verifyMfa`, `getMfaPolicy`, `setMfaPolicy` on `IdentityStore`. Wires the MFA primitives behind a single store-level surface so adopters don't write the orchestration themselves.

## [v0.2.0-rc.2] — 2026-04-26

WebAuthn RS256 + EdDSA assertion verification per ADR 0010.

## [v0.2.0-rc.1] — 2026-04-25

Initial v0.2 release-candidate. See [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md) for the spec-level summary of v0.2.

For pre-rc history, see git tags.
