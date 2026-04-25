// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type { FastifyInstance } from "fastify";

import type { CredId, UsrId } from "@flametrench/identity";

import { buildBearerAuthHook } from "../auth.js";
import type { FlametrenchServerConfig } from "../types.js";

type VerifyBody = {
  type: "password";
  identifier: string;
  proof: { password: string };
};

type CreateBody =
  | {
      usr_id: UsrId;
      type: "password";
      identifier: string;
      password: string;
    }
  | {
      usr_id: UsrId;
      type: "passkey";
      identifier: string;
      public_key: string; // base64 in the wire; we treat it as opaque bytes for the store
      sign_count: number;
      rp_id: string;
    }
  | {
      usr_id: UsrId;
      type: "oidc";
      identifier: string;
      oidc_issuer: string;
      oidc_subject: string;
    };

export async function registerCredentialRoutes(
  app: FastifyInstance,
  config: FlametrenchServerConfig,
): Promise<void> {
  const auth = buildBearerAuthHook(config);

  // POST /v1/credentials — create. Public (needed during sign-up).
  app.post<{ Body: CreateBody }>("/credentials", async (request, reply) => {
    const body = request.body;
    let cred;
    switch (body.type) {
      case "password":
        cred = await config.identityStore.createCredential({
          type: "password",
          usrId: body.usr_id,
          identifier: body.identifier,
          password: body.password,
        });
        break;
      case "passkey":
        cred = await config.identityStore.createCredential({
          type: "passkey",
          usrId: body.usr_id,
          identifier: body.identifier,
          publicKey: Buffer.from(body.public_key, "base64"),
          signCount: body.sign_count,
          rpId: body.rp_id,
        });
        break;
      case "oidc":
        cred = await config.identityStore.createCredential({
          type: "oidc",
          usrId: body.usr_id,
          identifier: body.identifier,
          oidcIssuer: body.oidc_issuer,
          oidcSubject: body.oidc_subject,
        });
        break;
    }
    reply.code(201).send(cred);
  });

  // POST /v1/credentials/verify — password verification. Public (pre-login).
  app.post<{ Body: VerifyBody }>("/credentials/verify", async (request) => {
    const body = request.body;
    if (body.type !== "password") {
      // Passkey/OIDC verification happens in the application layer for v0.0.1.
      return Response.json(
        { code: "not_implemented", message: "Only password verification is supported server-side in v0.0.1" },
        { status: 501 },
      );
    }
    const result = await config.identityStore.verifyPassword({
      type: "password",
      identifier: body.identifier,
      password: body.proof.password,
    });
    return { usr_id: result.usrId, cred_id: result.credId };
  });

  app.get<{ Params: { cred_id: CredId } }>(
    "/credentials/:cred_id",
    { onRequest: [auth] },
    async (request) => {
      return config.identityStore.getCredential(request.params.cred_id);
    },
  );

  app.post<{ Params: { cred_id: CredId } }>(
    "/credentials/:cred_id/suspend",
    { onRequest: [auth] },
    async (request) => {
      return config.identityStore.suspendCredential(request.params.cred_id);
    },
  );

  app.post<{ Params: { cred_id: CredId } }>(
    "/credentials/:cred_id/reinstate",
    { onRequest: [auth] },
    async (request) => {
      return config.identityStore.reinstateCredential(request.params.cred_id);
    },
  );

  app.post<{ Params: { cred_id: CredId } }>(
    "/credentials/:cred_id/revoke",
    { onRequest: [auth] },
    async (request) => {
      return config.identityStore.revokeCredential(request.params.cred_id);
    },
  );
}
