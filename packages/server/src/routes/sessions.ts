// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type { FastifyInstance } from "fastify";

import type { CredId, SesId, UsrId } from "@flametrench/identity";

import { buildBearerAuthHook, requireSession } from "../auth.js";
import type { FlametrenchServerConfig } from "../types.js";

export async function registerSessionRoutes(
  app: FastifyInstance,
  config: FlametrenchServerConfig,
): Promise<void> {
  const auth = buildBearerAuthHook(config);

  // POST /v1/sessions — login. Public.
  app.post<{
    Body: { usr_id: UsrId; cred_id: CredId; ttl_seconds: number };
  }>("/sessions", async (request, reply) => {
    const { usr_id, cred_id, ttl_seconds } = request.body;
    const { session, token } = await config.identityStore.createSession({
      usrId: usr_id,
      credId: cred_id,
      ttlSeconds: ttl_seconds,
    });
    reply.code(201).send({ session, token });
  });

  app.get<{ Params: { ses_id: SesId } }>(
    "/sessions/:ses_id",
    { onRequest: [auth] },
    async (request) => {
      return config.identityStore.getSession(request.params.ses_id);
    },
  );

  app.post<{ Params: { ses_id: SesId } }>(
    "/sessions/:ses_id/refresh",
    { onRequest: [auth] },
    async (request, reply) => {
      const result = await config.identityStore.refreshSession(
        request.params.ses_id,
      );
      reply.code(201).send(result);
    },
  );

  app.post<{ Params: { ses_id: SesId } }>(
    "/sessions/:ses_id/revoke",
    { onRequest: [auth] },
    async (request) => {
      return config.identityStore.revokeSession(request.params.ses_id);
    },
  );

  // Convenience: GET /v1/sessions/current returns the session attached by
  // the bearer-auth hook. Saves callers having to track their own session id.
  app.get("/sessions/current", { onRequest: [auth] }, async (request) => {
    return requireSession(request);
  });
}
