# Flametrench Node SDK

[![CI](https://github.com/flametrench/node/actions/workflows/ci.yml/badge.svg)](https://github.com/flametrench/node/actions/workflows/ci.yml)

Node SDK for [Flametrench](https://github.com/flametrench/spec). Monorepo of `@flametrench/*` packages.

## Packages

- [`@flametrench/ids`](./packages/ids) — Prefixed wire-format IDs for Flametrench. Stable. _v0.2.0-rc.2_
- [`@flametrench/identity`](./packages/identity) — Users, credentials (Argon2id-pinned password + passkey + OIDC), user-bound sessions with rotation on refresh, and v0.2 multi-factor authentication (TOTP + WebAuthn). In-memory + Postgres-backed stores. _v0.2.0-rc.4_
- [`@flametrench/tenancy`](./packages/tenancy) — Organizations, memberships, and invitations. In-memory + Postgres-backed stores. _v0.2.0-rc.5_
- [`@flametrench/authz`](./packages/authz) — Relational tuples and exact-match `check()` (v0.2 adds opt-in rewrite rules and time-bounded share tokens). In-memory + Postgres-backed stores. _v0.2.0-rc.4_
- [`@flametrench/nextjs`](./packages/nextjs) — Next.js 15 App Router adapter: cookie-backed session helpers, password sign-in, route handlers for `/api/auth/*`. _v0.0.1_
- [`@flametrench/server`](./packages/server) — Fastify 5 reference HTTP server exposing the v0.1 OpenAPI surface, backed by pluggable stores. Drop-in deployable starting point. _v0.0.1_

More framework adapters and platform-breadth primitives will follow once v0.2 final ships.

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
