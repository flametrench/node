// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type { FastifyInstance } from "fastify";

import type {
  InvId,
  OrgId,
  PreTuple,
  Role,
  UsrId,
} from "@flametrench/tenancy";

import { buildBearerAuthHook, requireSession } from "../auth.js";
import type { FlametrenchServerConfig } from "../types.js";

export async function registerInvitationRoutes(
  app: FastifyInstance,
  config: FlametrenchServerConfig,
): Promise<void> {
  const auth = buildBearerAuthHook(config);

  app.post<{
    Params: { org_id: OrgId };
    Body: {
      identifier: string;
      role: Role;
      expires_at: string;
      pre_tuples?: Array<{
        relation: string;
        object_type: string;
        object_id: string;
      }>;
    };
  }>(
    "/orgs/:org_id/invitations",
    { onRequest: [auth] },
    async (request, reply) => {
      const session = requireSession(request);
      const preTuples: PreTuple[] = (request.body.pre_tuples ?? []).map(
        (pt) => ({
          relation: pt.relation,
          objectType: pt.object_type,
          objectId: pt.object_id,
        }),
      );
      const inv = await config.tenancyStore.createInvitation({
        orgId: request.params.org_id,
        identifier: request.body.identifier,
        role: request.body.role,
        invitedBy: session.usrId,
        expiresAt: new Date(request.body.expires_at),
        preTuples,
      });
      reply.code(201).send(inv);
    },
  );

  app.get<{
    Params: { org_id: OrgId };
    Querystring: { cursor?: string; limit?: number; status?: string };
  }>("/orgs/:org_id/invitations", { onRequest: [auth] }, async (request) => {
    return config.tenancyStore.listInvitations(request.params.org_id, {
      cursor: request.query.cursor,
      limit: request.query.limit,
      status: request.query.status as never,
    });
  });

  app.get<{ Params: { inv_id: InvId } }>(
    "/invitations/:inv_id",
    { onRequest: [auth] },
    async (request) => {
      return config.tenancyStore.getInvitation(request.params.inv_id);
    },
  );

  app.post<{
    Params: { inv_id: InvId };
    Body?: { as_usr_id?: UsrId };
  }>(
    "/invitations/:inv_id/accept",
    { onRequest: [auth] },
    async (request) => {
      return config.tenancyStore.acceptInvitation({
        invId: request.params.inv_id,
        asUsrId: request.body?.as_usr_id,
      });
    },
  );

  app.post<{
    Params: { inv_id: InvId };
    Body?: { as_usr_id?: UsrId };
  }>(
    "/invitations/:inv_id/decline",
    { onRequest: [auth] },
    async (request) => {
      return config.tenancyStore.declineInvitation({
        invId: request.params.inv_id,
        asUsrId: request.body?.as_usr_id ?? null,
      });
    },
  );

  app.post<{ Params: { inv_id: InvId } }>(
    "/invitations/:inv_id/revoke",
    { onRequest: [auth] },
    async (request) => {
      const session = requireSession(request);
      return config.tenancyStore.revokeInvitation({
        invId: request.params.inv_id,
        adminUsrId: session.usrId,
      });
    },
  );
}
