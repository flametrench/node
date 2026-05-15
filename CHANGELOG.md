# Flametrench Node SDK — monorepo changelog

Top-level release log for `flametrench/node`. Per-package changelogs (the source of truth for any single package) live in:

- [`packages/ids/CHANGELOG.md`](./packages/ids/CHANGELOG.md)
- [`packages/identity/CHANGELOG.md`](./packages/identity/CHANGELOG.md)
- [`packages/tenancy/CHANGELOG.md`](./packages/tenancy/CHANGELOG.md)
- [`packages/authz/CHANGELOG.md`](./packages/authz/CHANGELOG.md)
- [`packages/server/CHANGELOG.md`](./packages/server/CHANGELOG.md)
- [`packages/nextjs/CHANGELOG.md`](./packages/nextjs/CHANGELOG.md)

Spec-level changes (the contract these packages implement) live in [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

## [v0.3.0] — 2026-05-15

The v0.3.0 cut at the monorepo level. All four core SDK packages snap to `0.3.0`; server bumps to `0.0.3`.

| Package | Previous | This release |
|---|---|---|
| `@flametrench/ids` | `0.2.0` | `0.3.0` — adds `pat_` prefix |
| `@flametrench/identity` | `0.2.1` | `0.3.0` — adds PAT primitive (ADR 0016), `AuthKind`, `classifyBearer` |
| `@flametrench/tenancy` | `0.2.1` | `0.3.0` — no surface changes; bumped for SDK matrix uniformity |
| `@flametrench/authz` | `0.2.1` | `0.3.0` — adds Postgres rewrite-rule evaluation (ADR 0017) |
| `@flametrench/server` | `0.0.2` | `0.0.3` — adds `resolveBearer()` for ADR 0016 prefix routing |
| `@flametrench/nextjs` | `0.0.1` | `0.0.1` (unchanged) |

**Highlights:**

- **Personal access tokens (ADR 0016)** — non-interactive bearer credentials for CLI / CI / service-to-service use. Wire format `pat_<32hex-id>_<base64url-secret>` (Stripe-style id-then-secret); the server's `resolveBearer()` helper prefix-routes incoming bearer tokens to session / share / PAT verifiers. Argon2id storage at the cred-password parameter floor; conflated `InvalidPatTokenError` shape on missing-row vs wrong-secret avoids a token-presence timing oracle.
- **Postgres rewrite-rule evaluation (ADR 0017)** — `PostgresTupleStore.check()` now accepts the same `rules` option as `InMemoryTupleStore` and evaluates via iterative async expansion. The internal evaluator becomes async-capable (`DirectLookup` / `ListByObject` callbacks return `Promise<...>`). Read-skew under concurrent writers is documented as an accepted v0.3 limitation; the fix-path is caller-owned-connection mode with `REPEATABLE READ`.
- **v0.3 security audit closed** — 32 findings, 22 fixed in code (most-severe: C1 SQL-array smuggle in PHP `checkAny`; relevant to Node: H2 PAT timing oracle, M1 rule-eval connection pinning, M9 `subjectIdToUuid` prefix assertion). Full table at [`spec/docs/security-audit-v0.3.md`](https://github.com/flametrench/spec/blob/main/docs/security-audit-v0.3.md).

**Adopter upgrade:**

```sh
pnpm add @flametrench/ids@^0.3.0 \
         @flametrench/identity@^0.3.0 \
         @flametrench/tenancy@^0.3.0 \
         @flametrench/authz@^0.3.0
```

Plus the single-statement schema migration documented in the migration guide:

```sql
ALTER TABLE tup DROP CONSTRAINT tup_subject_type_check;
ALTER TABLE tup ADD CONSTRAINT tup_subject_type_check
    CHECK (subject_type ~ '^[a-z]{2,6}$');
```

Full upgrade walkthrough at [`spec/docs/migrating-to-v0.3.md`](https://github.com/flametrench/spec/blob/main/docs/migrating-to-v0.3.md).

## [v0.2.1] — 2026-05-01

Patch-release across `identity`, `tenancy`, and `authz` to ship the ADR 0013 savepoint cooperation that `v0.2.0`'s built artifacts had missing. Server bumped to `0.0.2` to track the SDK 0.2.1 deps via `workspace:*` resolution. Root cause + remediation in each affected package's CHANGELOG and the v0.2.1 PR (`v021-savepoint-republish`).

## [v0.2.0] — 2026-04-30

v0.2 stable cutoff across `@flametrench/{ids,identity,tenancy,authz}`. Per-package CHANGELOGs carry the full surface list.
