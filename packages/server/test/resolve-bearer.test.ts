// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import {
  InvalidPatTokenError,
  InvalidTokenError,
  type Session,
  type VerifiedPat,
} from "@flametrench/identity";
import type { VerifiedShare } from "@flametrench/authz";

import {
  TOKEN_FORMAT_UNRECOGNIZED_CODE,
  TokenFormatUnrecognizedError,
  resolveBearer,
} from "../src/index.js";

// ─── Test doubles ───
//
// We don't need a full IdentityStore for these tests — resolveBearer
// only calls verifyPatToken / verifySessionToken, and only one per
// invocation. Single-method stubs keep the surface area honest about
// what the helper actually depends on.

function fakeIdentityStore(behavior: {
  verifyPatToken?: (token: string) => Promise<VerifiedPat>;
  verifySessionToken?: (token: string) => Promise<Session>;
}) {
  return {
    verifyPatToken:
      behavior.verifyPatToken ??
      (async () => {
        throw new Error("verifyPatToken not configured");
      }),
    verifySessionToken:
      behavior.verifySessionToken ??
      (async () => {
        throw new Error("verifySessionToken not configured");
      }),
  };
}

function fakeShareStore(verify: (token: string) => Promise<VerifiedShare>) {
  return { verifyShareToken: verify };
}

describe("resolveBearer — prefix dispatch (ADR 0016)", () => {
  it("routes pat_-prefixed tokens to verifyPatToken", async () => {
    const verified: VerifiedPat = {
      patId: "pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      usrId: "usr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      scope: ["repo:read"],
    };
    const calls: string[] = [];
    const result = await resolveBearer("pat_xxxx_yyyy", {
      identityStore: fakeIdentityStore({
        verifyPatToken: async (t) => {
          calls.push(`pat:${t}`);
          return verified;
        },
        verifySessionToken: async () => {
          throw new Error("session route should not be called for pat_ prefix");
        },
      }),
    });
    expect(result.kind).toBe("pat");
    if (result.kind === "pat") expect(result.verified).toEqual(verified);
    expect(calls).toEqual(["pat:pat_xxxx_yyyy"]);
  });

  it("routes shr_-prefixed tokens to verifyShareToken when shareStore is wired", async () => {
    const verified: VerifiedShare = {
      shareId: "shr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      objectType: "doc",
      objectId: "doc_x",
      relation: "viewer",
    };
    const result = await resolveBearer("shr_someshare", {
      identityStore: fakeIdentityStore({}),
      shareStore: fakeShareStore(async () => verified),
    });
    expect(result.kind).toBe("share");
    if (result.kind === "share") expect(result.verified).toEqual(verified);
  });

  it("falls through to verifySessionToken for any other prefix", async () => {
    const session = { id: "ses_xxx" } as unknown as Session;
    const calls: string[] = [];
    const result = await resolveBearer("opaque-session-token", {
      identityStore: fakeIdentityStore({
        verifySessionToken: async (t) => {
          calls.push(`session:${t}`);
          return session;
        },
        verifyPatToken: async () => {
          throw new Error("pat route should not be called for non-pat prefix");
        },
      }),
    });
    expect(result.kind).toBe("session");
    if (result.kind === "session") expect(result.session).toBe(session);
    expect(calls).toEqual(["session:opaque-session-token"]);
  });

  it("propagates InvalidPatTokenError unchanged for malformed PATs", async () => {
    await expect(
      resolveBearer("pat_garbage", {
        identityStore: fakeIdentityStore({
          verifyPatToken: async () => {
            throw new InvalidPatTokenError();
          },
        }),
      }),
    ).rejects.toBeInstanceOf(InvalidPatTokenError);
  });

  it("propagates InvalidTokenError from session verifier unchanged", async () => {
    await expect(
      resolveBearer("not-real", {
        identityStore: fakeIdentityStore({
          verifySessionToken: async () => {
            throw new InvalidTokenError("not a session");
          },
        }),
      }),
    ).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it("throws TokenFormatUnrecognizedError when shr_ comes in without a shareStore", async () => {
    await expect(
      resolveBearer("shr_token", {
        identityStore: fakeIdentityStore({}),
        // shareStore omitted
      }),
    ).rejects.toBeInstanceOf(TokenFormatUnrecognizedError);
  });

  it("TokenFormatUnrecognizedError carries the stable spec code", async () => {
    try {
      await resolveBearer("shr_token", {
        identityStore: fakeIdentityStore({}),
      });
      throw new Error("expected throw");
    } catch (err) {
      expect((err as TokenFormatUnrecognizedError).code).toBe(
        TOKEN_FORMAT_UNRECOGNIZED_CODE,
      );
    }
  });

  it("does NOT cross-route — a pat_-prefixed string never hits the session verifier", async () => {
    let sessionCalls = 0;
    await expect(
      resolveBearer("pat_xxxx_yyyy", {
        identityStore: fakeIdentityStore({
          verifyPatToken: async () => {
            throw new InvalidPatTokenError();
          },
          verifySessionToken: async () => {
            sessionCalls++;
            return {} as Session;
          },
        }),
      }),
    ).rejects.toBeInstanceOf(InvalidPatTokenError);
    expect(sessionCalls).toBe(0);
  });
});
