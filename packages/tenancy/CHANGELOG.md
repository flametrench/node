# Changelog

All notable changes to `@flametrench/tenancy` are recorded here.
Spec-level changes live in [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

## [v0.2.1] — 2026-05-01

### Fixed (release-process)
- Republish to ship the ADR 0013 savepoint-cooperation code that has been in source since commit `ff0b826` ("ADR 0013 Node rollout") but was missing from the published `v0.2.0` tarball. Without savepoint cooperation, `PostgresTenancyStore` constructed against a caller-owned `PoolClient` failed with `"Client has already been connected"` whenever a multi-statement method (e.g. `createOrg`) tried to `pool.connect()`. After v0.2.1, all multi-statement methods cooperate via `SAVEPOINT`/`RELEASE` when the adapter detects it was given a `PoolClient`, falling back to `BEGIN`/`COMMIT` when given a `Pool`.
- Added a `prepack` script (`pnpm build`) so future publishes always rebuild fresh `dist/` before tarballing.
- Added a regression test (`test/dist-savepoint.test.ts`) that asserts the bundled `dist/` contains the savepoint cooperation markers.

## [v0.2.0-rc.5] — 2026-04-27

### Fixed
- `PostgresTenancyStore.acceptInvitation` (when materializing pre-tuples) and `listTuplesForObject` now accept wire-format `object_id` values with app-defined prefixes (e.g. `proj_<32hex>`, `file_<32hex>`) in addition to bare 32-hex and canonical hyphenated UUIDs. Previously, an invitation carrying pre-tuples with wire-format prefixed IDs failed at acceptance time when binding to the UUID column. Closes [`spec#8`](https://github.com/flametrench/spec/issues/8).

## [v0.2.0-rc.4] — 2026-04-27

### Bumped
- Republish bookkeeping: the `0.2.0-rc.3` version slot on npm is permanently reserved (the previously published rc.3 was unpublished, and npm's tombstone rule prevents reuse of a version-name). No source changes; this RC ships the same surface that rc.3 carried in git.

## [v0.2.0-rc.3] — 2026-04-26

ADR 0011 org metadata (`name` + `slug`) — `UNSET` sentinel for partial updates, slug-format validation, `OrgSlugConflictError`. Postgres-backed `PostgresTenancyStore` mirroring `InMemoryTenancyStore` byte-for-byte at the SDK boundary, with multi-statement atomicity for `createOrg` + owner-membership + tuple, `changeRole` revoke-and-re-add, `acceptInvitation` with pre-tuples, and `transferOwnership`.

## [v0.2.0-rc.1] — 2026-04-25

Initial v0.2 release-candidate.

For pre-rc history, see git tags.
