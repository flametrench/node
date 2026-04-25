// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type { FastifyInstance } from "fastify";

import type { MemId, OrgId, UsrId } from "@flametrench/tenancy";

import { buildBearerAuthHook, requireSession } from "../auth.js";
import type { FlametrenchServerConfig } from "../types.js";

export async function registerMembershipRoutes(
  app: FastifyInstance,
  config: FlametrenchServerConfig,
): Promise<void> {
  const auth = buildBearerAuthHook(config);

  app.get<{ Params: { org_id: OrgId; mem_id: MemId } }>(
    "/orgs/:org_id/members/:mem_id",
    { onRequest: [auth] },
    async (request) => {
      return config.tenancyStore.getMembership(request.params.mem_id);
    },
  );

  app.post<{
    Params: { org_id: OrgId; mem_id: MemId };
    Body: { new_role: "owner" | "admin" | "member" | "guest" | "viewer" | "editor" };
  }>(
    "/orgs/:org_id/members/:mem_id/change-role",
    { onRequest: [auth] },
    async (request) => {
      return config.tenancyStore.changeRole({
        memId: request.params.mem_id,
        newRole: request.body.new_role,
      });
    },
  );

  app.post<{ Params: { org_id: OrgId; mem_id: MemId } }>(
    "/orgs/:org_id/members/:mem_id/suspend",
    { onRequest: [auth] },
    async (request) => {
      return config.tenancyStore.suspendMembership(request.params.mem_id);
    },
  );

  app.post<{ Params: { org_id: OrgId; mem_id: MemId } }>(
    "/orgs/:org_id/members/:mem_id/reinstate",
    { onRequest: [auth] },
    async (request) => {
      return config.tenancyStore.reinstateMembership(request.params.mem_id);
    },
  );

  app.post<{
    Params: { org_id: OrgId; mem_id: MemId };
    Body?: { transferTo?: UsrId };
  }>(
    "/orgs/:org_id/members/:mem_id/self-leave",
    { onRequest: [auth] },
    async (request) => {
      return config.tenancyStore.selfLeave({
        memId: request.params.mem_id,
        transferTo: request.body?.transferTo,
      });
    },
  );

  app.post<{ Params: { org_id: OrgId; mem_id: MemId } }>(
    "/orgs/:org_id/members/:mem_id/admin-remove",
    { onRequest: [auth] },
    async (request) => {
      const session = requireSession(request);
      return config.tenancyStore.adminRemove({
        memId: request.params.mem_id,
        adminUsrId: session.usrId,
      });
    },
  );
}
