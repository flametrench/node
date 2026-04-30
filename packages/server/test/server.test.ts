// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";

import { InMemoryTupleStore } from "@flametrench/authz";
import { InMemoryIdentityStore } from "@flametrench/identity";
import { InMemoryTenancyStore } from "@flametrench/tenancy";

import { createFlametrenchServer } from "../src/index.js";

describe("@flametrench/server (integration via inject)", () => {
  let app: FastifyInstance;
  let identityStore: InMemoryIdentityStore;
  let tenancyStore: InMemoryTenancyStore;
  let tupleStore: InMemoryTupleStore;

  beforeAll(async () => {
    identityStore = new InMemoryIdentityStore();
    tenancyStore = new InMemoryTenancyStore();
    tupleStore = new InMemoryTupleStore();
    app = await createFlametrenchServer({
      identityStore,
      tenancyStore,
      tupleStore,
    });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  // We DON'T reset stores between tests so that we can chain through a
  // realistic flow (sign-up → login → create org → invite → accept).
  // Each `describe` block uses fresh actors but shares the underlying app.

  describe("auth flow: sign-up → login", () => {
    let userId: string;
    let credId: string;
    let bearerToken: string;

    it("POST /v1/users — public, returns 201", async () => {
      const res = await app.inject({ method: "POST", url: "/v1/users" });
      expect(res.statusCode).toBe(201);
      const user = res.json();
      expect(user.id).toMatch(/^usr_[0-9a-f]{32}$/);
      expect(user.status).toBe("active");
      userId = user.id;
    });

    it("POST /v1/credentials — public, returns 201 for password type", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/v1/credentials",
        payload: {
          usr_id: userId,
          type: "password",
          identifier: "alice@example.com",
          password: "correcthorsebatterystaple",
        },
      });
      expect(res.statusCode).toBe(201);
      const cred = res.json();
      expect(cred.type).toBe("password");
      credId = cred.id;
    });

    it("POST /v1/credentials/verify — returns usr_id + cred_id on success", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/v1/credentials/verify",
        payload: {
          type: "password",
          identifier: "alice@example.com",
          proof: { password: "correcthorsebatterystaple" },
        },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.usr_id).toBe(userId);
      expect(body.cred_id).toBe(credId);
    });

    it("POST /v1/credentials/verify — 401 on bad password", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/v1/credentials/verify",
        payload: {
          type: "password",
          identifier: "alice@example.com",
          proof: { password: "wrong" },
        },
      });
      expect(res.statusCode).toBe(401);
      expect(res.json().code).toBe("unauthorized.invalid_credential");
    });

    it("POST /v1/sessions — returns 201 with session + opaque token", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/v1/sessions",
        payload: {
          usr_id: userId,
          cred_id: credId,
          ttl_seconds: 3600,
        },
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.session.id).toMatch(/^ses_/);
      expect(body.token).toBeTypeOf("string");
      expect(body.token).not.toBe(body.session.id); // opaque token != session id
      bearerToken = body.token;
    });

    it("GET /v1/sessions/current — returns the live session given the bearer token", async () => {
      const res = await app.inject({
        method: "GET",
        url: "/v1/sessions/current",
        headers: { authorization: `Bearer ${bearerToken}` },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().usrId).toBe(userId);
    });

    it("GET /v1/sessions/current — 401 without bearer", async () => {
      const res = await app.inject({
        method: "GET",
        url: "/v1/sessions/current",
      });
      expect(res.statusCode).toBe(401);
    });

    it("GET /v1/sessions/current — 401 with malformed bearer", async () => {
      const res = await app.inject({
        method: "GET",
        url: "/v1/sessions/current",
        headers: { authorization: "Bearer not-a-real-token" },
      });
      expect(res.statusCode).toBe(401);
    });
  });

  // Re-set up an authenticated context for the remaining suites.
  let session: { token: string; sesId: string; userId: string };

  async function freshAuthedUser() {
    const u = await identityStore.createUser();
    const c = await identityStore.createCredential({
      usrId: u.id,
      type: "password",
      identifier: `${Math.random()}@example.com`,
      password: "correcthorsebatterystaple",
    });
    const sw = await identityStore.createSession({
      usrId: u.id,
      credId: c.id,
      ttlSeconds: 3600,
    });
    return { token: sw.token, sesId: sw.session.id, userId: u.id };
  }

  beforeEach(async () => {
    session = await freshAuthedUser();
  });

  // ─── Org flow ───

  describe("org + membership flow", () => {
    it("POST /v1/orgs creates org with creator as owner", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/v1/orgs",
        headers: { authorization: `Bearer ${session.token}` },
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.org.status).toBe("active");
      expect(body.ownerMembership.role).toBe("owner");
      expect(body.ownerMembership.usrId).toBe(session.userId);
    });

    it("end-to-end: create org, add member, change role, list members, self-leave non-owner", async () => {
      // Create org as session's user.
      const createRes = await app.inject({
        method: "POST",
        url: "/v1/orgs",
        headers: { authorization: `Bearer ${session.token}` },
      });
      const orgId = createRes.json().org.id;
      // Create another user for the membership target.
      const target = await identityStore.createUser();
      // Add member.
      const addRes = await app.inject({
        method: "POST",
        url: `/v1/orgs/${orgId}/members`,
        headers: { authorization: `Bearer ${session.token}` },
        payload: { usr_id: target.id, role: "member" },
      });
      expect(addRes.statusCode).toBe(201);
      const memId = addRes.json().id;
      // Change role.
      const roleRes = await app.inject({
        method: "POST",
        url: `/v1/orgs/${orgId}/members/${memId}/change-role`,
        headers: { authorization: `Bearer ${session.token}` },
        payload: { new_role: "admin" },
      });
      expect(roleRes.statusCode).toBe(200);
      const newMem = roleRes.json();
      expect(newMem.replaces).toBe(memId);
      expect(newMem.role).toBe("admin");
      // List members.
      const listRes = await app.inject({
        method: "GET",
        url: `/v1/orgs/${orgId}/members?status=active`,
        headers: { authorization: `Bearer ${session.token}` },
      });
      expect(listRes.statusCode).toBe(200);
      expect(listRes.json().data.length).toBeGreaterThanOrEqual(2);
      // Self-leave the new admin (target is now an admin via newMem.id).
      const leaveRes = await app.inject({
        method: "POST",
        url: `/v1/orgs/${orgId}/members/${newMem.id}/self-leave`,
        headers: { authorization: `Bearer ${session.token}` },
      });
      expect(leaveRes.statusCode).toBe(200);
      expect(leaveRes.json().status).toBe("revoked");
      expect(leaveRes.json().removedBy).toBeNull();
    });

    it("self-leave as sole owner without transferTo returns 409 sole_owner", async () => {
      const createRes = await app.inject({
        method: "POST",
        url: "/v1/orgs",
        headers: { authorization: `Bearer ${session.token}` },
      });
      const ownerMemId = createRes.json().ownerMembership.id;
      const leaveRes = await app.inject({
        method: "POST",
        url: `/v1/orgs/${createRes.json().org.id}/members/${ownerMemId}/self-leave`,
        headers: { authorization: `Bearer ${session.token}` },
      });
      expect(leaveRes.statusCode).toBe(409);
      expect(leaveRes.json().code).toBe("conflict.sole_owner");
    });
  });

  // ─── Invitation flow ───

  describe("invitation flow", () => {
    it("end-to-end: create invitation, accept, see materialized membership", async () => {
      // alice (signed in via the outer describe) invites carol@example.com.
      const createRes = await app.inject({
        method: "POST",
        url: "/v1/orgs",
        headers: { authorization: `Bearer ${session.token}` },
      });
      const orgId = createRes.json().org.id;
      const expiresAt = new Date(Date.now() + 3600_000).toISOString();
      const invRes = await app.inject({
        method: "POST",
        url: `/v1/orgs/${orgId}/invitations`,
        headers: { authorization: `Bearer ${session.token}` },
        payload: {
          identifier: "carol@example.com",
          role: "member",
          expires_at: expiresAt,
        },
      });
      expect(invRes.statusCode).toBe(201);
      const invId = invRes.json().id;

      // carol signs up + signs in. She owns a credential whose identifier
      // byte-matches the invitation — that's the ADR 0009 binding.
      const carolSignup = await app.inject({ method: "POST", url: "/v1/users" });
      const carolId = carolSignup.json().id;
      await app.inject({
        method: "POST",
        url: "/v1/credentials",
        payload: {
          usr_id: carolId,
          type: "password",
          identifier: "carol@example.com",
          password: "carol-password-long-enough",
        },
      });
      const carolVerify = await app.inject({
        method: "POST",
        url: "/v1/credentials/verify",
        payload: {
          type: "password",
          identifier: "carol@example.com",
          proof: { password: "carol-password-long-enough" },
        },
      });
      const carolSes = await app.inject({
        method: "POST",
        url: "/v1/sessions",
        payload: {
          usr_id: carolVerify.json().usr_id,
          cred_id: carolVerify.json().cred_id,
          ttl_seconds: 3600,
        },
      });
      const carolBearer = carolSes.json().token;

      const acceptRes = await app.inject({
        method: "POST",
        url: `/v1/invitations/${invId}/accept`,
        headers: { authorization: `Bearer ${carolBearer}` },
        payload: {
          as_usr_id: carolId,
          accepting_identifier: "carol@example.com",
        },
      });
      expect(acceptRes.statusCode).toBe(200);
      const result = acceptRes.json();
      expect(result.invitation.status).toBe("accepted");
      expect(result.membership.usrId).toBe(carolId);
      expect(result.membership.role).toBe("member");
    });

    it("rejects accept when accepting_identifier is not bound to the bearer", async () => {
      // alice invites mallory@example.com.
      const createRes = await app.inject({
        method: "POST",
        url: "/v1/orgs",
        headers: { authorization: `Bearer ${session.token}` },
      });
      const orgId = createRes.json().org.id;
      const invRes = await app.inject({
        method: "POST",
        url: `/v1/orgs/${orgId}/invitations`,
        headers: { authorization: `Bearer ${session.token}` },
        payload: {
          identifier: "mallory@example.com",
          role: "member",
          expires_at: new Date(Date.now() + 3600_000).toISOString(),
        },
      });
      const invId = invRes.json().id;

      // dave signs in but DOESN'T own mallory@example.com — server must
      // refuse to forward the claim to the SDK.
      const daveSignup = await app.inject({ method: "POST", url: "/v1/users" });
      const daveId = daveSignup.json().id;
      await app.inject({
        method: "POST",
        url: "/v1/credentials",
        payload: {
          usr_id: daveId,
          type: "password",
          identifier: "dave@example.com",
          password: "dave-password-long-enough",
        },
      });
      const daveVerify = await app.inject({
        method: "POST",
        url: "/v1/credentials/verify",
        payload: {
          type: "password",
          identifier: "dave@example.com",
          proof: { password: "dave-password-long-enough" },
        },
      });
      const daveSes = await app.inject({
        method: "POST",
        url: "/v1/sessions",
        payload: {
          usr_id: daveVerify.json().usr_id,
          cred_id: daveVerify.json().cred_id,
          ttl_seconds: 3600,
        },
      });
      const daveBearer = daveSes.json().token;

      const acceptRes = await app.inject({
        method: "POST",
        url: `/v1/invitations/${invId}/accept`,
        headers: { authorization: `Bearer ${daveBearer}` },
        payload: {
          as_usr_id: daveId,
          accepting_identifier: "mallory@example.com",
        },
      });
      expect(acceptRes.statusCode).toBe(403);
      expect(acceptRes.json().code).toBe("forbidden.identifier_unowned");
    });
  });

  // ─── Tuples / authz check ───

  describe("authz check", () => {
    it("POST /v1/tuples + POST /v1/tuples/check round-trip with no-derivation invariant", async () => {
      const subjectId = (await identityStore.createUser()).id;
      // Create a tuple: subject = some user, relation = editor, object = proj_42.
      const create = await app.inject({
        method: "POST",
        url: "/v1/tuples",
        headers: { authorization: `Bearer ${session.token}` },
        payload: {
          subject_type: "usr",
          subject_id: subjectId,
          relation: "editor",
          object_type: "proj",
          object_id: "0190f2a8-1b3c-7abc-8123-456789abcdef",
        },
      });
      expect(create.statusCode).toBe(201);

      // Exact-match check: editor → allowed.
      const ok = await app.inject({
        method: "POST",
        url: "/v1/tuples/check",
        headers: { authorization: `Bearer ${session.token}` },
        payload: {
          subject_type: "usr",
          subject_id: subjectId,
          relation: "editor",
          object_type: "proj",
          object_id: "0190f2a8-1b3c-7abc-8123-456789abcdef",
        },
      });
      expect(ok.statusCode).toBe(200);
      expect(ok.json().allowed).toBe(true);

      // No-derivation: viewer → not allowed (admin/editor don't imply viewer in v0.1).
      const noDerive = await app.inject({
        method: "POST",
        url: "/v1/tuples/check",
        headers: { authorization: `Bearer ${session.token}` },
        payload: {
          subject_type: "usr",
          subject_id: subjectId,
          relation: "viewer",
          object_type: "proj",
          object_id: "0190f2a8-1b3c-7abc-8123-456789abcdef",
        },
      });
      expect(noDerive.statusCode).toBe(200);
      expect(noDerive.json().allowed).toBe(false);

      // Set form: relations=[viewer, editor] → allowed (editor matches).
      const setForm = await app.inject({
        method: "POST",
        url: "/v1/tuples/check",
        headers: { authorization: `Bearer ${session.token}` },
        payload: {
          subject_type: "usr",
          subject_id: subjectId,
          relations: ["viewer", "editor"],
          object_type: "proj",
          object_id: "0190f2a8-1b3c-7abc-8123-456789abcdef",
        },
      });
      expect(setForm.statusCode).toBe(200);
      expect(setForm.json().allowed).toBe(true);
    });
  });

  // ─── Error envelope shape ───

  describe("error envelopes", () => {
    it("not_found returns 404 with stable code", async () => {
      const res = await app.inject({
        method: "GET",
        url: `/v1/orgs/org_${"0".repeat(32)}`,
        headers: { authorization: `Bearer ${session.token}` },
      });
      expect(res.statusCode).toBe(404);
      expect(res.json().code).toBe("not_found");
    });

    it("invalid_format returns 400", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/v1/tuples",
        headers: { authorization: `Bearer ${session.token}` },
        payload: {
          subject_type: "usr",
          subject_id: session.userId,
          relation: "Owner", // uppercase rejected by spec
          object_type: "org",
          object_id: "0190f2a8-1b3c-7abc-8123-456789abcdef",
        },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().code).toBe("invalid_format.relation");
    });
  });
});
