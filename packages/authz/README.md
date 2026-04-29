# @flametrench/authz

Authorization primitives for [Flametrench](https://flametrench.dev): relational tuples and exact-match `check()`. Spec-conformant — exact-match remains the default, with **no implicit rewriting** at the API boundary ([ADR 0001](https://github.com/flametrench/spec/blob/main/decisions/0001-authorization-model.md)). v0.2 adds opt-in rewrite rules ([ADR 0007](https://github.com/flametrench/spec/blob/main/decisions/0007-rewrite-rules.md)) — `computed_userset` (role implication) and `tuple_to_userset` (parent-child inheritance) — for adopters who want hierarchies. Group expansion remains deferred.

**Status:** v0.2.0-rc.5 (release candidate). Includes `ShareStore` ([ADR 0012](https://github.com/flametrench/spec/blob/main/decisions/0012-share-tokens.md)) and Postgres-backed adapters (`PostgresTupleStore`, `PostgresShareStore`). Per [ADR 0013](https://github.com/flametrench/spec/blob/main/decisions/0013-postgres-adapter-transaction-nesting.md) both Postgres stores accept a `pg.Pool` (standalone) or `pg.PoolClient` (adopter-managed transaction) and cooperate with adopter-side outer transactions via savepoints when nested. `PostgresTupleStore.createTuple` uses `INSERT ... ON CONFLICT (natural_key) DO NOTHING RETURNING` so a duplicate-tuple attempt doesn't poison an outer transaction.

## Install

```bash
pnpm add @flametrench/authz
```

## Quick start

```ts
import { InMemoryTupleStore } from "@flametrench/authz";

const store = new InMemoryTupleStore();

// Grant Alice editor on project 42.
await store.createTuple({
  subjectType: "usr",
  subjectId: "usr_0190...abc",
  relation: "editor",
  objectType: "proj",
  objectId: "0190...42",
});

// Exact-match check.
const { allowed } = await store.check({
  subjectType: "usr",
  subjectId: "usr_0190...abc",
  relation: "editor",
  objectType: "proj",
  objectId: "0190...42",
});
console.log(allowed); // true

// Set-form check: true if any tuple exists matching any relation.
const result = await store.checkAny({
  subjectType: "usr",
  subjectId: "usr_0190...abc",
  relations: ["owner", "admin", "editor"],
  objectType: "proj",
  objectId: "0190...42",
});
```

## API

Every backend implements the `TupleStore` interface:

```ts
interface TupleStore {
  createTuple(input): Promise<Tuple>;
  deleteTuple(id): Promise<void>;
  cascadeRevokeSubject(subjectType, subjectId): Promise<number>;

  check(input): Promise<CheckResult>;         // single relation
  checkAny(input): Promise<CheckResult>;      // set of relations (OR)

  getTuple(id): Promise<Tuple>;
  listTuplesBySubject(subjectType, subjectId, options?): Promise<Page<Tuple>>;
  listTuplesByObject(objectType, objectId, relation?, options?): Promise<Page<Tuple>>;
}
```

`CheckResult = { allowed: boolean; matchedTupleId: TupId | null }`.

## What's explicitly excluded from v0.1

The `check()` contract is **exact match only**. If you need implication, inheritance, or group expansion, the spec's Pattern A (materialize tuples at state-change time) or Pattern B (pass a relation set to `checkAny`) are the sanctioned workarounds. See [`docs/authorization.md`](https://github.com/flametrench/spec/blob/main/docs/authorization.md) for the full pattern discussion.

`admin` does NOT imply `editor`. `editor` does NOT imply `viewer`. Being a `member` of an org does NOT imply any relation on objects owned by that org. The test suite includes fixtures for each of these invariants — they catch the most common class of bug when a conformant SDK accidentally introduces derivation.

## Format rules

- **Relation names** MUST match `/^[a-z_]{2,32}$/`. Six built-in relations (`owner`, `admin`, `member`, `guest`, `viewer`, `editor`) carry spec-intended semantics; applications may register custom relations (`dispatcher`, `approver`, etc.) matching the same pattern.
- **Object-type prefixes** MUST match `/^[a-z]{2,6}$/` per `docs/ids.md`. This means custom application object types must use short prefixes — e.g. `proj` not `project`, `doc` not `document`.
- **Subject type** in v0.1 MUST be `"usr"`. Group subjects (`grp_`) are a v0.2+ addition.

## Errors

| Class | Code | When |
|---|---|---|
| `TupleNotFoundError` | `not_found` | `getTuple` / `deleteTuple` on an unknown id. |
| `DuplicateTupleError` | `conflict.duplicate_tuple` | A tuple with the identical 5-tuple key already exists. Carries `existingTupleId` on the error instance. |
| `InvalidFormatError` | `invalid_format.<field>` | A relation name or object-type prefix violates the spec's format rules. |
| `EmptyRelationSetError` | `invalid_format.relations` | `checkAny` called with an empty relations array. |

## Integrating with `@flametrench/tenancy`

`@flametrench/tenancy` maintains `mem_`/`tup_` duality internally but does not yet import this package. Future versions will wire tenancy operations to a `TupleStore` so membership creation/deletion updates a shared tuple store. For now, the two packages can coexist; applications that need unified authz queries can query the tenancy store's `listTuplesForSubject` / `listTuplesForObject` methods.

## License

Apache License 2.0. Copyright 2026 NDC Digital, LLC.
