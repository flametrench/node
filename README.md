# Flametrench Node SDK

Node SDK for [Flametrench](https://github.com/flametrench/spec). Monorepo of `@flametrench/*` packages.

## Packages

- [`@flametrench/ids`](./packages/ids) — Prefixed wire-format IDs for Flametrench. Stable.
- [`@flametrench/tenancy`](./packages/tenancy) — Organizations, memberships, and invitations. In-memory + Postgres-backed stores (via `@flametrench/tenancy/postgres`).
- [`@flametrench/authz`](./packages/authz) — Relational tuples and exact-match `check()`. No rewrite rules in v0.1 per the spec.
- [`@flametrench/identity`](./packages/identity) — Users, credentials (Argon2id-pinned password + passkey + OIDC), and user-bound sessions with rotation on refresh.

More packages will land as the v0.1 specification stabilizes (Postgres stores for authz + identity, framework adapters).

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
