# Flametrench Node SDK

[![CI](https://github.com/flametrench/node/actions/workflows/ci.yml/badge.svg)](https://github.com/flametrench/node/actions/workflows/ci.yml)

Node SDK for [Flametrench](https://github.com/flametrench/spec). Monorepo of `@flametrench/*` packages.

## Packages

- [`@flametrench/ids`](./packages/ids) — Prefixed wire-format IDs for Flametrench (`usr_`, `org_`, `mem_`, `inv_`, `ses_`, `cred_`, `tup_`, `mfa_`, `shr_`, `pat_`). _v0.3.0_
- [`@flametrench/identity`](./packages/identity) — Users, credentials (Argon2id-pinned password + passkey + OIDC), user-bound sessions with rotation on refresh, v0.2 multi-factor authentication (TOTP + WebAuthn), `User.displayName` + `updateUser` (ADR 0014), `listUsers` (ADR 0015), and v0.3 personal access tokens with prefix-routed bearer classification + `AuthKind` audit discriminator (ADR 0016). In-memory + Postgres-backed stores. _v0.3.0_
- [`@flametrench/tenancy`](./packages/tenancy) — Organizations, memberships, and invitations. In-memory + Postgres-backed stores. _v0.3.0_ (no surface changes vs 0.2.1 — bumped for SDK matrix uniformity)
- [`@flametrench/authz`](./packages/authz) — Relational tuples and exact-match `check()` (v0.2 adds opt-in rewrite rules and time-bounded share tokens; v0.3 adds Postgres-backed rewrite-rule evaluation, ADR 0017). In-memory + Postgres-backed stores. _v0.3.0_
- [`@flametrench/nextjs`](./packages/nextjs) — Next.js 15 App Router adapter: cookie-backed session helpers, password sign-in, route handlers for `/api/auth/*`. _v0.0.1_
- [`@flametrench/server`](./packages/server) — Fastify 5 reference HTTP server exposing the v0.1 OpenAPI surface, backed by pluggable stores. v0.3 adds `resolveBearer()` for ADR 0016 prefix-routed bearer dispatch. Drop-in deployable starting point. _v0.0.3_

All four SDK packages snap to `v0.3.0` at the v0.3 cut. Migrating from v0.2? See [`spec/docs/migrating-to-v0.3.md`](https://github.com/flametrench/spec/blob/main/docs/migrating-to-v0.3.md) — the schema migration is one `ALTER TABLE` on `tup.subject_type`; PAT and Postgres rule-eval adoption are additive.

More framework adapters and platform-breadth primitives will follow.

## Development

```bash
pnpm install
pnpm -r build       # topological build (respects inter-package deps)
pnpm -r typecheck
pnpm -r test        # runs every package's test suite
```

`@flametrench/tenancy` depends on `@flametrench/ids` via a workspace reference; running `pnpm -r build` builds `ids` first so `tenancy`'s tests resolve it correctly.

## License

Apache License 2.0. Copyright 2026 NDC Digital, LLC.
