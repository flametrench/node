// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type { FastifyReply, FastifyRequest } from "fastify";

import type { IdentityStore } from "@flametrench/identity";

import { mapErrorToResponse } from "./errors.js";
import type { FlametrenchServerConfig } from "./types.js";

/**
 * Build a bearer-auth handler that can be attached as a Fastify `onRequest`
 * hook on routes that require authentication. Reads `Authorization: Bearer`,
 * verifies the token against the identity store, and attaches the resolved
 * session to `request.flametrenchSession`.
 *
 * On failure returns 401 with the mapped error envelope. The handler does
 * NOT continue the request.
 */
export function buildBearerAuthHook(config: FlametrenchServerConfig) {
  return async function bearerAuthHook(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> {
    const header = request.headers.authorization;
    if (!header || !header.startsWith("Bearer ")) {
      reply.code(401).send({
        code: "unauthenticated",
        message: "Missing or malformed Authorization header",
      });
      return;
    }
    const token = header.slice("Bearer ".length).trim();
    if (token.length === 0) {
      reply.code(401).send({
        code: "unauthenticated",
        message: "Empty bearer token",
      });
      return;
    }
    try {
      const session = await config.identityStore.verifySessionToken(token);
      request.flametrenchSession = session;
      if (config.onAuthenticated) await config.onAuthenticated(session);
    } catch (err) {
      const { status, envelope } = mapErrorToResponse(err);
      reply.code(status).send(envelope);
    }
  };
}

/**
 * Type-safe helper to extract the authenticated session inside a route
 * handler that's registered with the bearer-auth hook. Throws if called on
 * a route without the hook applied (programmer error).
 */
export function requireSession(
  request: FastifyRequest,
): NonNullable<FastifyRequest["flametrenchSession"]> {
  if (!request.flametrenchSession) {
    throw new Error(
      "requireSession called on a route without the bearer-auth hook",
    );
  }
  return request.flametrenchSession;
}

/** Pulls out the IdentityStore from a config; tiny helper so routes read cleanly. */
export function identityStoreOf(config: FlametrenchServerConfig): IdentityStore {
  return config.identityStore;
}
