// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type { FastifyInstance } from "fastify";

import type { UsrId } from "@flametrench/identity";

import { buildBearerAuthHook } from "../auth.js";
import type { FlametrenchServerConfig } from "../types.js";

/**
 * /v1/users endpoints.
 *
 * createUser is public (no auth required) because creating a new user is
 * typically the first step of sign-up. Lifecycle operations require an
 * authenticated session AND — in a real deployment — the caller would
 * additionally need admin rights to act on another user. For the reference
 * server, we enforce the "authenticated" bar and leave fine-grained
 * authorization to the application.
 */
export async function registerUserRoutes(
  app: FastifyInstance,
  config: FlametrenchServerConfig,
): Promise<void> {
  const auth = buildBearerAuthHook(config);

  app.post("/users", async (_request, reply) => {
    const user = await config.identityStore.createUser();
    reply.code(201).send(user);
  });

  app.get<{ Params: { usr_id: UsrId } }>(
    "/users/:usr_id",
    { onRequest: [auth] },
    async (request) => {
      return config.identityStore.getUser(request.params.usr_id);
    },
  );

  app.post<{ Params: { usr_id: UsrId } }>(
    "/users/:usr_id/suspend",
    { onRequest: [auth] },
    async (request) => {
      return config.identityStore.suspendUser(request.params.usr_id);
    },
  );

  app.post<{ Params: { usr_id: UsrId } }>(
    "/users/:usr_id/reinstate",
    { onRequest: [auth] },
    async (request) => {
      return config.identityStore.reinstateUser(request.params.usr_id);
    },
  );

  app.post<{ Params: { usr_id: UsrId } }>(
    "/users/:usr_id/revoke",
    { onRequest: [auth] },
    async (request) => {
      return config.identityStore.revokeUser(request.params.usr_id);
    },
  );
}
