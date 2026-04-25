# @flametrench/server

Reference HTTP server for [Flametrench](https://flametrench.dev) v0.1. A Fastify 5 app exposing the v0.1 OpenAPI surface, backed by pluggable stores (`@flametrench/identity`, `@flametrench/tenancy`, `@flametrench/authz`).

**Status:** v0.0.1 — early. Drop-in starting point for a Flametrench backend. For production deployments, swap the in-memory stores for Postgres-backed implementations (`@flametrench/tenancy/postgres`; identity/authz Postgres adapters land in v0.0.2).

## Install

```bash
pnpm add @flametrench/server @flametrench/identity @flametrench/tenancy @flametrench/authz fastify
```

## Quick start

```ts
import { createFlametrenchServer } from "@flametrench/server";
import { InMemoryIdentityStore } from "@flametrench/identity";
import { InMemoryTenancyStore } from "@flametrench/tenancy";
import { InMemoryTupleStore } from "@flametrench/authz";

const app = await createFlametrenchServer({
  identityStore: new InMemoryIdentityStore(),
  tenancyStore: new InMemoryTenancyStore(),
  tupleStore: new InMemoryTupleStore(),
});

await app.listen({ port: 3000 });
console.log("Flametrench listening on :3000");
```

That's it. The app speaks the v0.1 OpenAPI contract: `POST /v1/users`, `POST /v1/sessions`, `POST /v1/orgs/:org_id/members`, `POST /v1/tuples/check`, etc. Every operation in [`spec/openapi/flametrench-v0.1.yaml`](https://github.com/flametrench/spec/blob/main/openapi/flametrench-v0.1.yaml) is wired up.

## Auth

The server reads `Authorization: Bearer <token>` on every authenticated route. The token is the value returned from `POST /v1/sessions` — the **opaque bearer token**, not the session id. Verification roundtrips through `IdentityStore.verifySessionToken`, which checks token-hash equality, expiry, and revocation. Failures return 401 with the appropriate `code`.

A small set of routes are unauthenticated:

- `POST /v1/users` — sign-up.
- `POST /v1/credentials` — credential creation, typically during sign-up.
- `POST /v1/credentials/verify` — pre-login verification.
- `POST /v1/sessions` — login.

Everything else requires a valid session.

## Error envelopes

Every non-2xx response is shaped `{ code, message, details? }` matching the OpenAPI Error schema. The mapping from SDK exceptions to HTTP status is stable:

| SDK error | HTTP status |
|---|---|
| `NotFoundError` (any package) | 404 |
| `InvalidCredentialError`, `InvalidTokenError`, `SessionExpiredError` | 401 |
| `ForbiddenError`, `RoleHierarchyError` | 403 |
| `SoleOwnerError`, `Duplicate*Error`, `AlreadyTerminalError`, `Invitation*Error`, `CredentialNotActiveError`, `CredentialTypeMismatchError`, `PreconditionError` | 409 |
| `InvalidFormatError`, `EmptyRelationSetError` | 400 |
| Any unknown error | 500 |

The `code` field on every envelope is the same value the SDK puts on the thrown exception. Clients should switch on `code`, not on `message` — message text is allowed to evolve.

## What's NOT in v0.0.1

- **Authorization on individual operations.** The server enforces "must be authenticated"; finer-grained checks (e.g. "only an admin can change another member's role") are delegated to the underlying tenancy store (which already enforces sole-owner protection, admin-hierarchy preconditions, etc.). Real deployments will likely add explicit `check(...)` gates per route — that's a v0.0.2 story.
- **Request schema validation.** Fastify supports JSON Schema natively; routes don't yet declare them. Inputs are validated by the SDK stores (which throw `InvalidFormatError` etc., mapped to 400). Adding schema-first validation is a polish item.
- **OpenAPI doc serving.** Adding `@fastify/swagger` to expose `/openapi.json` from the actual route registrations is straightforward in v0.0.2.
- **CORS, rate limiting, request logging.** All standard Fastify plugins; left to the application layer to configure to taste.

## License

Apache License 2.0. Copyright 2026 NDC Digital, LLC.
