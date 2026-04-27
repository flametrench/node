# Changelog

All notable changes to `@flametrench/authz` are recorded here.
Spec-level changes live in [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

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
