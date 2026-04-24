// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import {
  InvalidCredentialError,
  type CredId,
  type UsrId,
} from "@flametrench/identity";

import type { FlametrenchNextHelpers } from "./session.js";

/**
 * Wire-format of a request body for the password sign-in endpoint.
 * Surfaces directly from JSON; downstream code validates.
 */
interface SignInBody {
  identifier?: unknown;
  password?: unknown;
  ttlSeconds?: unknown;
}

interface CreateSessionBody {
  usrId?: unknown;
  credId?: unknown;
  ttlSeconds?: unknown;
}

function badRequest(message: string): Response {
  return Response.json(
    { code: "invalid_request", message },
    { status: 400 },
  );
}

function unauthorized(message: string): Response {
  return Response.json(
    { code: "unauthorized", message },
    { status: 401 },
  );
}

/**
 * Build a set of route handlers ready to drop into a Next.js App Router
 * project under `app/api/auth/`:
 *
 * @example
 *     // app/api/auth/sign-in/route.ts
 *     import { flametrench } from "@/app/_lib/flametrench";
 *     import { makeAuthRouteHandlers } from "@flametrench/nextjs";
 *     export const { POST } = makeAuthRouteHandlers(flametrench).signIn();
 *
 *     // app/api/auth/sign-out/route.ts
 *     export const { POST } = makeAuthRouteHandlers(flametrench).signOut();
 *
 *     // app/api/auth/me/route.ts
 *     export const { GET } = makeAuthRouteHandlers(flametrench).me();
 *
 *     // app/api/auth/refresh/route.ts
 *     export const { POST } = makeAuthRouteHandlers(flametrench).refresh();
 *
 * Each helper returns an object with the appropriate HTTP method handlers
 * — Next's App Router exports its handlers via named HTTP-method exports,
 * so the destructuring pattern matches the framework's idiom directly.
 */
export function makeAuthRouteHandlers(helpers: FlametrenchNextHelpers) {
  return {
    /** `POST /api/auth/sign-in` — body `{ identifier, password, ttlSeconds? }`. */
    signIn() {
      return {
        POST: async (req: Request): Promise<Response> => {
          let body: SignInBody;
          try {
            body = (await req.json()) as SignInBody;
          } catch {
            return badRequest("Body must be JSON");
          }
          const identifier = body.identifier;
          const password = body.password;
          if (typeof identifier !== "string" || typeof password !== "string") {
            return badRequest("identifier and password are required strings");
          }
          const ttlSeconds =
            typeof body.ttlSeconds === "number" ? body.ttlSeconds : undefined;
          try {
            const session = await helpers.signInWithPassword({
              identifier,
              password,
              ttlSeconds,
            });
            return Response.json({ session });
          } catch (e) {
            if (e instanceof InvalidCredentialError) {
              return unauthorized("Invalid credentials");
            }
            throw e;
          }
        },
      };
    },

    /**
     * `POST /api/auth/sessions` — body `{ usrId, credId, ttlSeconds? }`.
     * Use this when password verification happens elsewhere (e.g.
     * passkey assertion verified by the application) and you just need
     * to mint a session.
     */
    createSession() {
      return {
        POST: async (req: Request): Promise<Response> => {
          let body: CreateSessionBody;
          try {
            body = (await req.json()) as CreateSessionBody;
          } catch {
            return badRequest("Body must be JSON");
          }
          if (typeof body.usrId !== "string" || typeof body.credId !== "string") {
            return badRequest("usrId and credId are required strings");
          }
          const ttlSeconds =
            typeof body.ttlSeconds === "number" ? body.ttlSeconds : undefined;
          const session = await helpers.createSession({
            usrId: body.usrId as UsrId,
            credId: body.credId as CredId,
            ttlSeconds,
          });
          return Response.json({ session });
        },
      };
    },

    /** `POST /api/auth/sign-out` — revokes current session, clears cookie. */
    signOut() {
      return {
        POST: async (): Promise<Response> => {
          await helpers.signOut();
          return Response.json({ ok: true });
        },
      };
    },

    /** `POST /api/auth/refresh` — rotates current session. */
    refresh() {
      return {
        POST: async (): Promise<Response> => {
          const session = await helpers.refreshSession();
          if (!session) return unauthorized("No active session");
          return Response.json({ session });
        },
      };
    },

    /** `GET /api/auth/me` — returns the current session, or 401 if none. */
    me() {
      return {
        GET: async (): Promise<Response> => {
          const session = await helpers.getSession();
          if (!session) return unauthorized("No active session");
          return Response.json({ session });
        },
      };
    },
  };
}
