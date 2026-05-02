// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// security-audit-v0.3.md H5: focused tests for buildBearerAuthHook —
// case-insensitive scheme matching (RFC 6750 §2.1) + PAT/share
// dispatch via resolveBearer.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";

import {
  InMemoryIdentityStore,
  InvalidPatTokenError,
  type Session,
  type VerifiedPat,
} from "@flametrench/identity";
import { InMemoryTupleStore } from "@flametrench/authz";
import { InMemoryTenancyStore } from "@flametrench/tenancy";
import type { ShareStore, VerifiedShare } from "@flametrench/authz";

import { buildBearerAuthHook } from "../src/index.js";
import type { FlametrenchServerConfig } from "../src/types.js";

function fakeShareStore(verify: (token: string) => Promise<VerifiedShare>): ShareStore {
  // Only verifyShareToken is used by the hook; other methods throw.
  return {
    verifyShareToken: verify,
  } as unknown as ShareStore;
}

function makeConfig(identityStore: InMemoryIdentityStore): FlametrenchServerConfig {
  return {
    identityStore,
    tupleStore: new InMemoryTupleStore(),
    tenancyStore: new InMemoryTenancyStore(),
  };
}

describe("buildBearerAuthHook (security-audit H5)", () => {
  let identityStore: InMemoryIdentityStore;
  let app: FastifyInstance;

  beforeEach(() => {
    identityStore = new InMemoryIdentityStore({
      patLastUsedCoalesceSeconds: 0,
    });
    app = Fastify();
  });

  afterEach(async () => {
    await app.close();
  });

  it("accepts the lowercase 'bearer' scheme (RFC 6750 §2.1)", async () => {
    const u = await identityStore.createUser();
    await identityStore.createCredential({
      usrId: u.id,
      type: "password",
      identifier: "alice@example.com",
      password: "correcthorsebatterystaple",
    });
    const verified = await identityStore.verifyPassword({
      identifier: "alice@example.com",
      password: "correcthorsebatterystaple",
    });
    const session = await identityStore.createSession({
      usrId: verified.usrId,
      credId: verified.credId,
      ttlSeconds: 3600,
    });

    const hook = buildBearerAuthHook(makeConfig(identityStore));
    app.addHook("onRequest", hook);
    app.get("/echo", async (request) => ({
      session_id: request.flametrenchSession?.id ?? null,
    }));

    const res = await app.inject({
      method: "GET",
      url: "/echo",
      headers: { authorization: `bearer ${session.token}` }, // lowercase
    });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).session_id).toBe(session.session.id);
  });

  it("accepts the UPPERCASE 'BEARER' scheme", async () => {
    const u = await identityStore.createUser();
    await identityStore.createCredential({
      usrId: u.id,
      type: "password",
      identifier: "alice@example.com",
      password: "correcthorsebatterystaple",
    });
    const verified = await identityStore.verifyPassword({
      identifier: "alice@example.com",
      password: "correcthorsebatterystaple",
    });
    const session = await identityStore.createSession({
      usrId: verified.usrId,
      credId: verified.credId,
      ttlSeconds: 3600,
    });

    const hook = buildBearerAuthHook(makeConfig(identityStore));
    app.addHook("onRequest", hook);
    app.get("/echo", async () => ({ ok: true }));

    const res = await app.inject({
      method: "GET",
      url: "/echo",
      headers: { authorization: `BEARER ${session.token}` },
    });
    expect(res.statusCode).toBe(200);
  });

  it("dispatches a pat_ bearer to verifyPatToken and populates request.flametrenchPat", async () => {
    const u = await identityStore.createUser();
    const r = await identityStore.createPat({
      usrId: u.id,
      name: "cli",
      scope: ["repo:read"],
    });

    const hook = buildBearerAuthHook(makeConfig(identityStore));
    app.addHook("onRequest", hook);
    app.get("/echo", async (request) => ({
      pat_id: request.flametrenchPat?.patId ?? null,
      scope: request.flametrenchPat?.scope ?? null,
      session_id: request.flametrenchSession?.id ?? null,
    }));

    const res = await app.inject({
      method: "GET",
      url: "/echo",
      headers: { authorization: `Bearer ${r.token}` },
    });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.pat_id).toBe(r.pat.id);
    expect(body.scope).toEqual(["repo:read"]);
    expect(body.session_id).toBeNull();
  });

  it("rejects an invalid pat_ bearer with 401", async () => {
    const hook = buildBearerAuthHook(makeConfig(identityStore));
    app.addHook("onRequest", hook);
    app.get("/echo", async () => ({ ok: true }));

    const res = await app.inject({
      method: "GET",
      url: "/echo",
      headers: { authorization: `Bearer pat_${"a".repeat(32)}_garbage` },
    });
    expect(res.statusCode).toBe(401);
    expect(JSON.parse(res.body).code).toBe("pat.invalid");
  });

  it("dispatches a shr_ bearer when shareStore is wired", async () => {
    const fakeVerified: VerifiedShare = {
      shareId: "shr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      objectType: "ticket",
      objectId: "ticket_xyz",
      relation: "viewer",
    };
    const shareStore = fakeShareStore(async () => fakeVerified);
    const hook = buildBearerAuthHook(makeConfig(identityStore), shareStore);
    app.addHook("onRequest", hook);
    app.get("/echo", async (request) => ({
      share_id: request.flametrenchShare?.shareId ?? null,
      relation: request.flametrenchShare?.relation ?? null,
    }));

    const res = await app.inject({
      method: "GET",
      url: "/echo",
      headers: { authorization: "Bearer shr_anytoken" },
    });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).share_id).toBe(fakeVerified.shareId);
  });

  it("rejects a shr_ bearer with 401 when no shareStore is wired", async () => {
    const hook = buildBearerAuthHook(makeConfig(identityStore));
    app.addHook("onRequest", hook);
    app.get("/echo", async () => ({ ok: true }));

    const res = await app.inject({
      method: "GET",
      url: "/echo",
      headers: { authorization: "Bearer shr_anytoken" },
    });
    expect(res.statusCode).toBe(401);
    expect(JSON.parse(res.body).code).toBe("auth.token_format_unrecognized");
  });

  it("rejects missing/empty Authorization with 401 unauthenticated", async () => {
    const hook = buildBearerAuthHook(makeConfig(identityStore));
    app.addHook("onRequest", hook);
    app.get("/echo", async () => ({ ok: true }));

    const res = await app.inject({ method: "GET", url: "/echo" });
    expect(res.statusCode).toBe(401);
    expect(JSON.parse(res.body).code).toBe("unauthenticated");
  });

  it("rejects a Basic auth header with 401 unauthenticated", async () => {
    const hook = buildBearerAuthHook(makeConfig(identityStore));
    app.addHook("onRequest", hook);
    app.get("/echo", async () => ({ ok: true }));

    const res = await app.inject({
      method: "GET",
      url: "/echo",
      headers: { authorization: "Basic dXNlcjpwYXNz" },
    });
    expect(res.statusCode).toBe(401);
    expect(JSON.parse(res.body).code).toBe("unauthenticated");
  });
});
