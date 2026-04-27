# Changelog

All notable changes to `@flametrench/tenancy` are recorded here.
Spec-level changes live in [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

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
