// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type { FastifyInstance } from "fastify";

import type { MemId, OrgId, UsrId } from "@flametrench/tenancy";

import { buildBearerAuthHook, requireSession } from "../auth.js";
import type { FlametrenchServerConfig } from "../types.js";

export async function registerOrgRoutes(
  app: FastifyInstance,
  config: FlametrenchServerConfig,
): Promise<void> {
  const auth = buildBearerAuthHook(config);

  // POST /v1/orgs — creator is the authenticated user.
  app.post("/orgs", { onRequest: [auth] }, async (request, reply) => {
    const session = requireSession(request);
    const result = await config.tenancyStore.createOrg(session.usrId);
    reply.code(201).send(result);
  });

  app.get<{ Params: { org_id: OrgId } }>(
    "/orgs/:org_id",
    { onRequest: [auth] },
    async (request) => {
      return config.tenancyStore.getOrg(request.params.org_id);
    },
  );

  app.post<{ Params: { org_id: OrgId } }>(
    "/orgs/:org_id/suspend",
    { onRequest: [auth] },
    async (request) => {
      return config.tenancyStore.suspendOrg(request.params.org_id);
    },
  );

  app.post<{ Params: { org_id: OrgId } }>(
    "/orgs/:org_id/reinstate",
    { onRequest: [auth] },
    async (request) => {
      return config.tenancyStore.reinstateOrg(request.params.org_id);
    },
  );

  app.post<{ Params: { org_id: OrgId } }>(
    "/orgs/:org_id/revoke",
    { onRequest: [auth] },
    async (request) => {
      return config.tenancyStore.revokeOrg(request.params.org_id);
    },
  );

  app.post<{
    Params: { org_id: OrgId };
    Body: { from_mem_id: MemId; to_mem_id: MemId };
  }>(
    "/orgs/:org_id/transfer-ownership",
    { onRequest: [auth] },
    async (request) => {
      return config.tenancyStore.transferOwnership({
        orgId: request.params.org_id,
        fromMemId: request.body.from_mem_id,
        toMemId: request.body.to_mem_id,
      });
    },
  );

  // Member add + list. Member operations that reference a specific mem_id
  // live in memberships.ts to keep files bounded.
  app.post<{
    Params: { org_id: OrgId };
    Body: {
      usr_id: UsrId;
      role: "owner" | "admin" | "member" | "guest" | "viewer" | "editor";
      invited_by?: UsrId;
    };
  }>("/orgs/:org_id/members", { onRequest: [auth] }, async (request, reply) => {
    const m = await config.tenancyStore.addMember({
      orgId: request.params.org_id,
      usrId: request.body.usr_id,
      role: request.body.role,
      invitedBy: request.body.invited_by,
    });
    reply.code(201).send(m);
  });

  app.get<{
    Params: { org_id: OrgId };
    Querystring: { cursor?: string; limit?: number; status?: string };
  }>("/orgs/:org_id/members", { onRequest: [auth] }, async (request) => {
    return config.tenancyStore.listMembers(request.params.org_id, {
      cursor: request.query.cursor,
      limit: request.query.limit,
      status: request.query.status as never,
    });
  });
}
