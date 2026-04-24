# Flametrench Node SDK

Node SDK for [Flametrench](https://github.com/flametrench/spec). Monorepo of `@flametrench/*` packages.

## Packages

- [`@flametrench/ids`](./packages/ids) — Prefixed wire-format IDs for Flametrench. Stable.
- [`@flametrench/tenancy`](./packages/tenancy) — Organizations, memberships, and invitations. Includes an in-memory reference store; a Postgres-backed store is planned.

More packages will land as the v0.1 specification stabilizes (identity, authorization, framework adapters).

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
