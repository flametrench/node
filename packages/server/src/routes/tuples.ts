// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type { FastifyInstance } from "fastify";

import type { SubjectType, TupId } from "@flametrench/authz";

import { buildBearerAuthHook, requireSession } from "../auth.js";
import type { FlametrenchServerConfig } from "../types.js";

export async function registerTupleRoutes(
  app: FastifyInstance,
  config: FlametrenchServerConfig,
): Promise<void> {
  const auth = buildBearerAuthHook(config);

  app.post<{
    Body: {
      subject_type: SubjectType;
      subject_id: string;
      relation: string;
      object_type: string;
      object_id: string;
    };
  }>("/tuples", { onRequest: [auth] }, async (request, reply) => {
    const session = requireSession(request);
    const tup = await config.tupleStore.createTuple({
      subjectType: request.body.subject_type,
      subjectId: request.body.subject_id as never,
      relation: request.body.relation,
      objectType: request.body.object_type,
      objectId: request.body.object_id,
      createdBy: session.usrId,
    });
    reply.code(201).send(tup);
  });

  app.delete<{ Params: { tup_id: TupId } }>(
    "/tuples/:tup_id",
    { onRequest: [auth] },
    async (request, reply) => {
      await config.tupleStore.deleteTuple(request.params.tup_id);
      reply.code(204).send();
    },
  );

  app.post<{
    Body: {
      subject_type: SubjectType;
      subject_id: string;
      relation?: string;
      relations?: string[];
      object_type: string;
      object_id: string;
    };
  }>("/tuples/check", { onRequest: [auth] }, async (request) => {
    const body = request.body;
    if (body.relations !== undefined) {
      const r = await config.tupleStore.checkAny({
        subjectType: body.subject_type,
        subjectId: body.subject_id as never,
        relations: body.relations,
        objectType: body.object_type,
        objectId: body.object_id,
      });
      return { allowed: r.allowed, matched_tuple_id: r.matchedTupleId };
    }
    if (body.relation !== undefined) {
      const r = await config.tupleStore.check({
        subjectType: body.subject_type,
        subjectId: body.subject_id as never,
        relation: body.relation,
        objectType: body.object_type,
        objectId: body.object_id,
      });
      return { allowed: r.allowed, matched_tuple_id: r.matchedTupleId };
    }
    return { code: "invalid_request", message: "Must provide `relation` or `relations`" };
  });

  app.get<{
    Querystring: {
      subject_type: SubjectType;
      subject_id: string;
      cursor?: string;
      limit?: number;
    };
  }>("/tuples/by-subject", { onRequest: [auth] }, async (request) => {
    return config.tupleStore.listTuplesBySubject(
      request.query.subject_type,
      request.query.subject_id as never,
      { cursor: request.query.cursor, limit: request.query.limit },
    );
  });

  app.get<{
    Querystring: {
      object_type: string;
      object_id: string;
      relation?: string;
      cursor?: string;
      limit?: number;
    };
  }>("/tuples/by-object", { onRequest: [auth] }, async (request) => {
    return config.tupleStore.listTuplesByObject(
      request.query.object_type,
      request.query.object_id,
      request.query.relation,
      { cursor: request.query.cursor, limit: request.query.limit },
    );
  });
}
