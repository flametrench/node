# Changelog

All notable changes to `@flametrench/authz` are recorded here.
Spec-level changes live in [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

## [v0.3.0] — 2026-05-15

### Added (Postgres rewrite-rule evaluation, ADR 0017)
- `PostgresTupleStore` constructor accepts a new optional `rules` parameter mirroring `InMemoryTupleStore`. When set, `check()` evaluates rewrite rules via iterative async expansion against Postgres (one indexed SELECT per direct lookup; recursive over `computed_userset`; one SELECT per `tuple_to_userset` enumeration). Cycle detection, depth + fan-out bounds, and short-circuit semantics from ADR 0007 are preserved verbatim.
- `PostgresTupleStore` constructor also accepts `maxDepth` (default 8) and `maxFanOut` (default 1024) — the same evaluation bounds as `InMemoryTupleStore`.
- New `subjectIdToUuid` accepts wire-format ids with any registered prefix (e.g. `org_<hex>`), not just `usr_<hex>`. Required for `tuple_to_userset` patterns where the parent hop is a non-`usr` object.
- New `postgres-rewrite-rules.test.ts` mirrors `rewrite-rules.test.ts` against the live Postgres adapter (11 tests covering `computed_userset` chains, `tuple_to_userset` parent inheritance, cycle detection, depth-limit, and `checkAny` fast-path / rules-path).

### Changed
- **`evaluate()` (internal rewrite-rule evaluator) is now async-capable** per ADR 0017. `DirectLookup` and `ListByObject` callbacks return `Promise<...>`. `InMemoryTupleStore` wraps the synchronous map probe in `Promise.resolve(...)`; `PostgresTupleStore` issues real async queries. Adopters who called `evaluate()` directly (a small set; most use `tupleStore.check()`) MUST migrate to `await evaluate(...)`.
- `PostgresTupleStore.check()` and `checkAny()` now route through the rule-aware path when `rules` is set. With `rules` unset (or `{}`), behavior is byte-identical to v0.2.

### Test infrastructure
- `postgres-schema.sql` re-synced from spec `reference/postgres.sql` to pick up the relaxed `tup.subject_type` constraint (now `^[a-z]{2,6}$` per ADR 0017 follow-up). The v0.1/v0.2 `subject_type IN ('usr')` constraint silently blocked `tuple_to_userset` patterns; lifting it is additive.

## [v0.2.1] — 2026-05-01

### Fixed (release-process)
- Republish to ship the ADR 0013 savepoint-cooperation code that has been in source since commit `ff0b826` ("ADR 0013 Node rollout") but was missing from the published `v0.2.0` tarball. Both `PostgresTupleStore` and `PostgresShareStore` now cooperate with a caller-owned `PoolClient` via `SAVEPOINT`/`RELEASE` for multi-statement methods (e.g. share verification, single-use consumption), falling back to `BEGIN`/`COMMIT` when given a `Pool`.
- Added a `prepack` script (`pnpm build`) so future publishes always rebuild fresh `dist/` before tarballing.
- Added a regression test (`test/dist-savepoint.test.ts`) that asserts the bundled `dist/` contains the savepoint cooperation markers.

## [v0.2.0] — 2026-04-30

### Released
- v0.2 stable cutoff. No functional changes from `v0.2.0-rc.4` — same source, version bumped to drop the `-rc` suffix at the spec v0.2.0 freeze. Published to npm `latest` dist-tag. **Note:** the v0.2.0 tarball shipped with stale built artifacts predating the ADR 0013 savepoint cooperation in source — see the v0.2.1 entry above. The `0.2.0` version remains on npm but consumers should pin `^0.2.1` for the savepoint code path.

## [v0.2.0-rc.4] — 2026-04-27

### Fixed
- `PostgresTupleStore` (`createTuple`, `checkAny`, `listTuplesByObject`) and `PostgresShareStore` (`createShare`, `listSharesForObject`) now accept wire-format `object_id` values with app-defined prefixes (e.g. `proj_<32hex>`, `file_<32hex>`) in addition to bare 32-hex and canonical hyphenated UUIDs. Previously, binding a wire-format `object_id` directly to the UUID column raised a Postgres parse error. `object_type` is application-defined per ADR 0001, so adopters legitimately pass wire-format prefixed IDs at this boundary. Closes [`spec#8`](https://github.com/flametrench/spec/issues/8).

## [v0.2.0-rc.3] — 2026-04-27

### Added
- `ShareStore` interface and two implementations — `InMemoryShareStore` (always exported) and `PostgresShareStore` (at `@flametrench/authz/postgres`). Implements [ADR 0012](https://github.com/flametrench/spec/blob/main/decisions/0012-share-tokens.md)'s share-token primitive: time-bounded, presentation-bearer access to a single resource without minting an authenticated principal. Closes [`spec#7`](https://github.com/flametrench/spec/issues/7).
  - Token storage matches `ses`: SHA-256 → 32 bytes `BYTEA`, constant-time compare.
  - Verification ordering is normative: revoked > consumed > expired > success.
  - `single_use` shares consume on first verify via `UPDATE … WHERE consumed_at IS NULL RETURNING …`, so concurrent verifies of a single-use token race-correctly to exactly one success and one `ShareConsumedError`.
  - 365-day spec ceiling on `expiresInSeconds`; `InvalidFormatError` raised for over-long lifetimes.
  - New error classes: `InvalidShareTokenError`, `ShareExpiredError`, `ShareRevokedError`, `ShareConsumedError`, `ShareNotFoundError`.
- 33 new tests (18 in-memory + 15 Postgres); Postgres set gated on `AUTHZ_POSTGRES_URL`.

### Changed
- `vitest.config.ts` — `fileParallelism: false` so Postgres integration test files (which share one database) don't race the schema reset.

## [v0.2.0-rc.2] — 2026-04-27

### Added
- `PostgresTupleStore` (new export at `@flametrench/authz/postgres`) — a Postgres-backed `TupleStore`. Mirrors `InMemoryTupleStore` byte-for-byte at the SDK boundary; the difference is durability and concurrency.
  - Schema: `spec/reference/postgres.sql` (the `tup` table). Apply before constructing the store.
  - Connection: accepts a `pg.Pool`. `pg ^8.11.0` declared as an optional peer dep — adopters using only the in-memory store don't pull it in.
  - Coverage: 15 integration tests, gated on `AUTHZ_POSTGRES_URL`.
- Rewrite-rule support (ADR 0007) is exact-match only in the Postgres store; bridging the synchronous evaluator to async DB I/O is tracked for v0.3. Adopters with rule needs can pull the relevant tuple subset into memory and use `InMemoryTupleStore` with the `rules` option.

## [v0.2.0-rc.1] — 2026-04-25

Initial v0.2 release-candidate. ADR 0007 rewrite rules in `InMemoryTupleStore`. See [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md) for the spec-level summary.

For pre-rc history, see git tags.
