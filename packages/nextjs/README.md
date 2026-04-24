# @flametrench/nextjs

Next.js 15 App Router adapter for [Flametrench](https://flametrench.dev). Wires `@flametrench/identity` into Next's cookie-based session model with a thin, opinionated surface: server-component session helpers, password sign-in, session rotation, and route-handler factories for the `/api/auth/*` family.

**Status:** v0.0.1 — early alongside the other `@flametrench/*` packages.

## Install

```bash
pnpm add @flametrench/nextjs @flametrench/identity
# next and react are peer deps you already have
```

## Setup

Create one shared instance bound to your identity store and Next's `cookies()` accessor. Keep it module-level so the same store is used across server components and route handlers.

```ts
// app/_lib/flametrench.ts
import { cookies } from "next/headers";
import { InMemoryIdentityStore } from "@flametrench/identity";
import { createFlametrenchNext } from "@flametrench/nextjs";

// In production, swap this for a real backend (Postgres adapter coming soon).
const identityStore = new InMemoryIdentityStore();

export const flametrench = createFlametrenchNext({
  identityStore,
  cookies,
});
```

## Server-component usage

```tsx
// app/page.tsx
import { flametrench } from "./_lib/flametrench";

export default async function Page() {
  const session = await flametrench.getSession();
  return session
    ? <p>Welcome back, {session.usrId}.</p>
    : <a href="/sign-in">Sign in</a>;
}
```

For pages that **require** auth, use `requireSession()` — it throws `UnauthenticatedError`, which you can catch with a Next error boundary or wrap to redirect:

```tsx
// app/dashboard/page.tsx
import { redirect } from "next/navigation";
import { flametrench } from "../_lib/flametrench";
import { UnauthenticatedError } from "@flametrench/nextjs";

export default async function Page() {
  try {
    const session = await flametrench.requireSession();
    return <Dashboard usrId={session.usrId} />;
  } catch (e) {
    if (e instanceof UnauthenticatedError) redirect("/sign-in");
    throw e;
  }
}
```

## Route handlers

The package ships a factory that returns ready-made handlers for the common `/api/auth/*` routes. Each helper is a discrete export so you wire only the routes you need:

```ts
// app/api/auth/sign-in/route.ts
import { flametrench } from "@/app/_lib/flametrench";
import { makeAuthRouteHandlers } from "@flametrench/nextjs";
export const { POST } = makeAuthRouteHandlers(flametrench).signIn();

// app/api/auth/sign-out/route.ts
import { flametrench } from "@/app/_lib/flametrench";
import { makeAuthRouteHandlers } from "@flametrench/nextjs";
export const { POST } = makeAuthRouteHandlers(flametrench).signOut();

// app/api/auth/me/route.ts
import { flametrench } from "@/app/_lib/flametrench";
import { makeAuthRouteHandlers } from "@flametrench/nextjs";
export const { GET } = makeAuthRouteHandlers(flametrench).me();

// app/api/auth/refresh/route.ts
import { flametrench } from "@/app/_lib/flametrench";
import { makeAuthRouteHandlers } from "@flametrench/nextjs";
export const { POST } = makeAuthRouteHandlers(flametrench).refresh();
```

All five handlers (`signIn`, `signOut`, `me`, `refresh`, plus a lower-level `createSession` for cases where you've already verified credentials elsewhere — e.g. passkey assertion) follow Next's named-method-export convention exactly.

## Cookie defaults

| Field | Default | Override via |
|---|---|---|
| Cookie name | `flametrench_session` | `cookieOptions.name` |
| `HttpOnly` | always | (not configurable) |
| `Secure` | `true` when `NODE_ENV === "production"` | `cookieOptions.secure` |
| `SameSite` | `lax` | `cookieOptions.sameSite` |
| `Path` | `/` | `cookieOptions.path` |
| Default TTL | 7 days | `cookieOptions.defaultTtlSeconds` |

The cookie value is the **opaque bearer token** issued by `@flametrench/identity`, not the session id — same separation the spec mandates (`docs/identity.md` §"Session ID versus session token"). Verifying the token uses the identity store's `verifySessionToken`, which checks expiry, revocation, and the SHA-256 token hash.

## What this adapter is NOT

- **It's not an auth UI.** Sign-in / sign-out forms are application code; this package gives you the verbs (`signInWithPassword`, `signOut`, etc.) and the route handlers that back them.
- **It's not multi-tenant aware.** Tenancy + authz wiring stays at the application level for v0.0.1 — `getSession()` returns the bare session, and the caller queries `@flametrench/tenancy` and `@flametrench/authz` for org context and permission checks. A future `getSessionWithContext()` may bundle that.
- **It's not a JWT issuer.** The bearer token is opaque; verification is server-side via the identity store. If you want stateless JWT-style sessions, swap in a different `IdentityStore` implementation that mints JWTs internally — the adapter is store-agnostic.

## License

Apache License 2.0. Copyright 2026 NDC Digital, LLC.
