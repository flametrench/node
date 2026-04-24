// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * @flametrench/nextjs — Next.js 15 App Router adapter.
 *
 * Wires @flametrench/identity into Next's cookie-based session model with
 * a thin, opinionated surface: server-component session helpers, password
 * sign-in flow, session rotation, and route-handler factories for
 * /api/auth/*.
 */

export type { CookieAccessor, CookieStore } from "./cookies.js";

export type {
  FlametrenchNextConfig,
  FlametrenchNextHelpers,
  SessionCookieOptions,
} from "./session.js";
export { createFlametrenchNext } from "./session.js";

export { makeAuthRouteHandlers } from "./route-handlers.js";

export {
  FlametrenchNextError,
  UnauthenticatedError,
} from "./errors.js";
