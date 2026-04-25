// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import Fastify, { type FastifyInstance } from "fastify";

import { mapErrorToResponse } from "./errors.js";
import { registerCredentialRoutes } from "./routes/credentials.js";
import { registerInvitationRoutes } from "./routes/invitations.js";
import { registerMembershipRoutes } from "./routes/memberships.js";
import { registerOrgRoutes } from "./routes/orgs.js";
import { registerSessionRoutes } from "./routes/sessions.js";
import { registerTupleRoutes } from "./routes/tuples.js";
import { registerUserRoutes } from "./routes/users.js";
import type { FlametrenchServerConfig } from "./types.js";

/**
 * Build a Fastify app that serves the Flametrench v0.1 OpenAPI surface.
 *
 * The returned app is a standard Fastify instance — start it with
 * `app.listen({ port: 3000 })`, or exercise it in tests via `app.inject()`.
 *
 * @example
 *     import Fastify from "fastify";
 *     import { createFlametrenchServer } from "@flametrench/server";
 *     import { InMemoryIdentityStore } from "@flametrench/identity";
 *     import { InMemoryTenancyStore } from "@flametrench/tenancy";
 *     import { InMemoryTupleStore } from "@flametrench/authz";
 *
 *     const app = await createFlametrenchServer({
 *       identityStore: new InMemoryIdentityStore(),
 *       tenancyStore: new InMemoryTenancyStore(),
 *       tupleStore: new InMemoryTupleStore(),
 *     });
 *     await app.listen({ port: 3000 });
 */
export async function createFlametrenchServer(
  config: FlametrenchServerConfig,
): Promise<FastifyInstance> {
  const app = Fastify({
    // Disable Fastify's default logger in the returned app; callers can
    // configure logging by passing fastifyOptions in a future release.
    logger: false,
  });

  // Unified error handler. Every SDK error maps to a stable HTTP status
  // and envelope matching the OpenAPI Error schema.
  app.setErrorHandler(async (err, _request, reply) => {
    const { status, envelope } = mapErrorToResponse(err);
    reply.code(status).send(envelope);
  });

  const prefix = config.prefix ?? "/v1";

  await app.register(
    async (scope) => {
      await registerUserRoutes(scope, config);
      await registerSessionRoutes(scope, config);
      await registerCredentialRoutes(scope, config);
      await registerOrgRoutes(scope, config);
      await registerMembershipRoutes(scope, config);
      await registerInvitationRoutes(scope, config);
      await registerTupleRoutes(scope, config);
    },
    { prefix },
  );

  return app;
}
