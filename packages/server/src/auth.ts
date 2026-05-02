// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type { FastifyReply, FastifyRequest } from "fastify";

import type { IdentityStore } from "@flametrench/identity";
import type { ShareStore } from "@flametrench/authz";

import { mapErrorToResponse } from "./errors.js";
import { resolveBearer } from "./resolve-bearer.js";
import type { FlametrenchServerConfig } from "./types.js";

/**
 * security-audit-v0.3.md H5: pre-fix this hook only routed sessions
 * — every PAT bearer fell through to verifySessionToken and got
 * InvalidTokenError. Also, `startsWith("Bearer ")` was case-sensitive
 * (RFC 6750 §2.1 requires case-insensitive scheme matching).
 *
 * Build a bearer-auth handler that can be attached as a Fastify
 * `onRequest` hook on routes that require authentication. Reads
 * `Authorization: Bearer` (case-insensitive scheme per RFC 6750),
 * routes the token via {@link resolveBearer} so PAT and share
 * bearers are dispatched to the right verifier alongside sessions,
 * and attaches the resolved principal to the request.
 *
 * Result attachments on the request (mutually exclusive — exactly
 * one is set on success):
 *   - `request.flametrenchSession` — for session bearers
 *   - `request.flametrenchPat`     — for PAT bearers (v0.3+)
 *   - `request.flametrenchShare`   — for share bearers (when
 *                                     shareStore is wired)
 *
 * The legacy `request.flametrenchSession` field stays the canonical
 * surface for v0.1/v0.2 routes that pre-date PATs; new routes that
 * accept multiple bearer kinds should switch on `auth.kind` from
 * the resolved record.
 *
 * On failure returns 401 with the mapped error envelope. The handler
 * does NOT continue the request.
 *
 * @param shareStore Optional. When wired, `shr_…` bearers route to
 *     `verifyShareToken`. When omitted, `shr_…` bearers fail with
 *     `auth.token_format_unrecognized` (per resolveBearer's contract).
 */
export function buildBearerAuthHook(
  config: FlametrenchServerConfig,
  shareStore?: ShareStore,
) {
  return async function bearerAuthHook(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> {
    const header = request.headers.authorization;
    // RFC 6750 §2.1: bearer scheme is case-insensitive ("Bearer" =
    // "bearer" = "BEARER"). lowercase the prefix portion before
    // comparing.
    if (!header || header.length < 7 || header.slice(0, 7).toLowerCase() !== "bearer ") {
      reply.code(401).send({
        code: "unauthenticated",
        message: "Missing or malformed Authorization header",
      });
      return;
    }
    const token = header.slice(7).trim();
    if (token.length === 0) {
      reply.code(401).send({
        code: "unauthenticated",
        message: "Empty bearer token",
      });
      return;
    }
    try {
      const resolved = await resolveBearer(token, {
        identityStore: config.identityStore,
        shareStore,
      });
      switch (resolved.kind) {
        case "session": {
          request.flametrenchSession = resolved.session;
          if (config.onAuthenticated) await config.onAuthenticated(resolved.session);
          return;
        }
        case "pat": {
          request.flametrenchPat = resolved.verified;
          return;
        }
        case "share": {
          request.flametrenchShare = resolved.verified;
          return;
        }
      }
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
