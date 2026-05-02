// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * @flametrench/server — Fastify-based reference HTTP server for
 * Flametrench v0.1.
 *
 * Wires the pluggable store layer (`@flametrench/identity`,
 * `@flametrench/tenancy`, `@flametrench/authz`) into a Fastify app that
 * conforms to the v0.1 OpenAPI surface. Error envelopes, status codes,
 * and route shapes match the spec.
 */

export { createFlametrenchServer } from "./app.js";
export type { FlametrenchServerConfig } from "./types.js";
export { mapErrorToResponse, type ErrorEnvelope } from "./errors.js";
export { buildBearerAuthHook, requireSession } from "./auth.js";

// v0.3 — Bearer prefix dispatch for sessions / PATs / shares (ADR 0016).
export {
  TOKEN_FORMAT_UNRECOGNIZED_CODE,
  TokenFormatUnrecognizedError,
  classifyBearer,
  resolveBearer,
} from "./resolve-bearer.js";
export type {
  AuthKind,
  ResolveBearerStores,
  ResolvedBearer,
} from "./resolve-bearer.js";
