// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for v0.2 IdentityStore MFA operations. Cross-SDK parity
// is enforced by the conformance corpus and the per-primitive tests
// (totpCompute vectors, WebAuthn signature verification, recovery
// format). This file focuses on the store-level orchestration that
// ADR 0008 specifies.

import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  sign as cryptoSign,
} from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  InMemoryIdentityStore,
  InvalidCredentialError,
  PreconditionError,
  b64urlEncode,
  coseKeyEs256,
  isValidRecoveryCode,
  totpCompute,
  type UsrId,
} from "../src/index.js";

function ascii(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function makeMockClock(start: Date): {
  clock: () => Date;
  advance: (seconds: number) => void;
} {
  let now = start;
  return {
    clock: () => now,
    advance: (sec) => {
      now = new Date(now.getTime() + sec * 1000);
    },
  };
}

// ─── Recovery codes ─────────────────────────────────────────────

describe("recovery factor enrollment", () => {
  it("returns 10 codes, factor active immediately", async () => {
    const store = new InMemoryIdentityStore();
    const user = await store.createUser();
    const result = await store.enrollRecoveryFactor(user.id);
    expect(result.factor.status).toBe("active");
    expect(result.codes).toHaveLength(10);
    for (const c of result.codes) {
      expect(isValidRecoveryCode(c)).toBe(true);
    }
    expect(result.factor.remaining).toBe(10);
  });

  it("verify consumes a slot, same code is non-reusable", async () => {
    const store = new InMemoryIdentityStore();
    const user = await store.createUser();
    const enroll = await store.enrollRecoveryFactor(user.id);
    const code = enroll.codes[3]!;
    const result = await store.verifyMfa(user.id, { type: "recovery", code });
    expect(result.type).toBe("recovery");
    await expect(
      store.verifyMfa(user.id, { type: "recovery", code }),
    ).rejects.toThrow(InvalidCredentialError);
    const factor = await store.getMfaFactor(enroll.factor.id);
    expect((factor as { remaining: number }).remaining).toBe(9);
  });

  it("verify normalizes lowercase + whitespace", async () => {
    const store = new InMemoryIdentityStore();
    const user = await store.createUser();
    const enroll = await store.enrollRecoveryFactor(user.id);
    await store.verifyMfa(user.id, {
      type: "recovery",
      code: `  ${enroll.codes[0]!.toLowerCase()}  `,
    });
  });

  it("at most one active recovery factor per user", async () => {
    const store = new InMemoryIdentityStore();
    const user = await store.createUser();
    await store.enrollRecoveryFactor(user.id);
    await expect(store.enrollRecoveryFactor(user.id)).rejects.toThrow(
      PreconditionError,
    );
  });

  it("revoke frees the singleton slot for re-enrollment", async () => {
    const store = new InMemoryIdentityStore();
    const user = await store.createUser();
    const first = await store.enrollRecoveryFactor(user.id);
    await store.revokeMfaFactor(first.factor.id);
    const second = await store.enrollRecoveryFactor(user.id);
    expect(second.factor.id).not.toBe(first.factor.id);
  });
});

// ─── TOTP ────────────────────────────────────────────────────────

describe("TOTP factor enrollment", () => {
  it("enroll returns pending factor + secret + otpauth URI", async () => {
    const store = new InMemoryIdentityStore();
    const user = await store.createUser();
    const enroll = await store.enrollTotpFactor(user.id, "iPhone");
    expect(enroll.factor.status).toBe("pending");
    expect(enroll.secretB32).toMatch(/^[A-Z2-7]+$/);
    expect(enroll.otpauthUri).toMatch(/^otpauth:\/\/totp\//);
  });

  it("confirm with current code activates the factor", async () => {
    const { clock } = makeMockClock(new Date("2026-04-26T12:00:00Z"));
    const store = new InMemoryIdentityStore({ clock });
    const user = await store.createUser();
    const enroll = await store.enrollTotpFactor(user.id, "iPhone");
    const secret = base32Decode(enroll.secretB32);
    const code = totpCompute(secret, Math.floor(clock().getTime() / 1000));
    const confirmed = await store.confirmTotpFactor(enroll.factor.id, code);
    expect(confirmed.status).toBe("active");
  });

  it("confirm with wrong code rejects", async () => {
    const store = new InMemoryIdentityStore();
    const user = await store.createUser();
    const enroll = await store.enrollTotpFactor(user.id, "iPhone");
    await expect(
      store.confirmTotpFactor(enroll.factor.id, "000000"),
    ).rejects.toThrow(InvalidCredentialError);
  });

  it("confirm after pending TTL rejects with pending_factor_expired", async () => {
    const { clock, advance } = makeMockClock(new Date("2026-04-26T12:00:00Z"));
    const store = new InMemoryIdentityStore({ clock });
    const user = await store.createUser();
    const enroll = await store.enrollTotpFactor(user.id, "iPhone");
    advance(700); // past 600s TTL
    const secret = base32Decode(enroll.secretB32);
    const code = totpCompute(secret, Math.floor(clock().getTime() / 1000));
    await expect(
      store.confirmTotpFactor(enroll.factor.id, code),
    ).rejects.toMatchObject({
      code: "precondition.pending_factor_expired",
    });
  });

  it("at most one active TOTP factor per user (after confirm)", async () => {
    const { clock } = makeMockClock(new Date("2026-04-26T12:00:00Z"));
    const store = new InMemoryIdentityStore({ clock });
    const user = await store.createUser();
    const enroll = await store.enrollTotpFactor(user.id, "iPhone");
    const secret = base32Decode(enroll.secretB32);
    await store.confirmTotpFactor(
      enroll.factor.id,
      totpCompute(secret, Math.floor(clock().getTime() / 1000)),
    );
    await expect(
      store.enrollTotpFactor(user.id, "Backup"),
    ).rejects.toThrow(PreconditionError);
  });

  it("verify after confirm succeeds and reports type=totp", async () => {
    const { clock } = makeMockClock(new Date("2026-04-26T12:00:00Z"));
    const store = new InMemoryIdentityStore({ clock });
    const user = await store.createUser();
    const enroll = await store.enrollTotpFactor(user.id, "iPhone");
    const secret = base32Decode(enroll.secretB32);
    await store.confirmTotpFactor(
      enroll.factor.id,
      totpCompute(secret, Math.floor(clock().getTime() / 1000)),
    );
    const result = await store.verifyMfa(user.id, {
      type: "totp",
      code: totpCompute(secret, Math.floor(clock().getTime() / 1000)),
    });
    expect(result.type).toBe("totp");
    expect(result.mfaId).toBe(enroll.factor.id);
  });

  it("verify with no active TOTP factor rejects", async () => {
    const store = new InMemoryIdentityStore();
    const user = await store.createUser();
    await expect(
      store.verifyMfa(user.id, { type: "totp", code: "123456" }),
    ).rejects.toThrow(InvalidCredentialError);
  });
});

// ─── WebAuthn ────────────────────────────────────────────────────

describe("WebAuthn factor enrollment", () => {
  function makeKeypair(): { privateKey: ReturnType<typeof createPrivateKey>; cose: Uint8Array } {
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256",
    });
    const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
    const x = Buffer.from(jwk.x, "base64url");
    const y = Buffer.from(jwk.y, "base64url");
    return { privateKey, cose: coseKeyEs256(x, y) };
  }

  function makeAssertion(
    privateKey: ReturnType<typeof createPrivateKey>,
    rpId: string,
    origin: string,
    challenge: Uint8Array,
    signCount: number,
  ): { authenticatorData: Buffer; clientDataJson: Buffer; signature: Buffer } {
    const rpHash = createHash("sha256").update(rpId, "utf-8").digest();
    const authData = Buffer.alloc(37);
    rpHash.copy(authData, 0);
    authData[32] = 0x05; // UP+UV
    authData.writeUInt32BE(signCount, 33);
    const clientDataJson = Buffer.from(
      JSON.stringify({
        challenge: b64urlEncode(challenge),
        origin,
        type: "webauthn.get",
      }),
    );
    const clientHash = createHash("sha256").update(clientDataJson).digest();
    const signature = cryptoSign(
      "sha256",
      Buffer.concat([authData, clientHash]),
      { key: privateKey, dsaEncoding: "der" },
    );
    return { authenticatorData: authData, clientDataJson, signature };
  }

  it("enroll → confirm → verify flow advances counter", async () => {
    const store = new InMemoryIdentityStore();
    const user = await store.createUser();
    const { privateKey, cose } = makeKeypair();
    const credId = "test-credential-id";
    const rpId = "test.example";
    const origin = "https://test.example";
    const enroll = await store.enrollWebAuthnFactor({
      usrId: user.id,
      identifier: credId,
      publicKey: cose,
      signCount: 0,
      rpId,
    });
    expect(enroll.factor.status).toBe("pending");
    const challenge = ascii("confirm-challenge");
    const a1 = makeAssertion(privateKey, rpId, origin, challenge, 1);
    const confirmed = await store.confirmWebAuthnFactor({
      mfaId: enroll.factor.id,
      ...a1,
      expectedChallenge: challenge,
      expectedOrigin: origin,
    });
    expect(confirmed.status).toBe("active");
    expect(confirmed.signCount).toBe(1);

    const challenge2 = ascii("verify-challenge");
    const a2 = makeAssertion(privateKey, rpId, origin, challenge2, 2);
    const result = await store.verifyMfa(user.id, {
      type: "webauthn",
      credentialId: credId,
      authenticatorData: a2.authenticatorData,
      clientDataJson: a2.clientDataJson,
      signature: a2.signature,
      expectedChallenge: challenge2,
      expectedOrigin: origin,
    });
    expect(result.type).toBe("webauthn");
    expect(result.newSignCount).toBe(2);
  });

  it("multiple active WebAuthn factors permitted per user", async () => {
    const store = new InMemoryIdentityStore();
    const user = await store.createUser();
    const k1 = makeKeypair();
    const k2 = makeKeypair();
    const e1 = await store.enrollWebAuthnFactor({
      usrId: user.id,
      identifier: "cred-a",
      publicKey: k1.cose,
      signCount: 0,
      rpId: "x",
    });
    const e2 = await store.enrollWebAuthnFactor({
      usrId: user.id,
      identifier: "cred-b",
      publicKey: k2.cose,
      signCount: 0,
      rpId: "x",
    });
    expect(e1.factor.id).not.toBe(e2.factor.id);
  });

  it("duplicate credential id rejects", async () => {
    const store = new InMemoryIdentityStore();
    const user = await store.createUser();
    const { cose } = makeKeypair();
    await store.enrollWebAuthnFactor({
      usrId: user.id,
      identifier: "dup",
      publicKey: cose,
      signCount: 0,
      rpId: "x",
    });
    await expect(
      store.enrollWebAuthnFactor({
        usrId: user.id,
        identifier: "dup",
        publicKey: cose,
        signCount: 0,
        rpId: "x",
      }),
    ).rejects.toThrow(PreconditionError);
  });
});

// ─── Listing + revoke + policy ───────────────────────────────────

describe("listMfaFactors", () => {
  it("returns user-scoped factor set", async () => {
    const store = new InMemoryIdentityStore();
    const a = await store.createUser();
    const b = await store.createUser();
    await store.enrollRecoveryFactor(a.id);
    await store.enrollTotpFactor(a.id, "iPhone");
    await store.enrollRecoveryFactor(b.id);
    expect(await store.listMfaFactors(a.id)).toHaveLength(2);
    expect(await store.listMfaFactors(b.id)).toHaveLength(1);
  });
});

describe("usr_mfa_policy", () => {
  it("get defaults to null (absent row = MFA not required)", async () => {
    const store = new InMemoryIdentityStore();
    const user = await store.createUser();
    expect(await store.getMfaPolicy(user.id)).toBeNull();
  });

  it("set then get round-trip", async () => {
    const store = new InMemoryIdentityStore();
    const user = await store.createUser();
    const grace = new Date("2026-05-10T00:00:00Z");
    const policy = await store.setMfaPolicy({
      usrId: user.id,
      required: true,
      graceUntil: grace,
    });
    expect(policy.required).toBe(true);
    expect(policy.graceUntil).toEqual(grace);
    const fetched = await store.getMfaPolicy(user.id);
    expect(fetched).toEqual(policy);
  });

  it("set overwrites the row idempotently", async () => {
    const store = new InMemoryIdentityStore();
    const user = await store.createUser();
    await store.setMfaPolicy({ usrId: user.id, required: true });
    await store.setMfaPolicy({ usrId: user.id, required: false });
    const policy = await store.getMfaPolicy(user.id);
    expect(policy?.required).toBe(false);
  });
});

// ─── helpers ────────────────────────────────────────────────────

function base32Decode(s: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = s.replace(/=+$/, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const i = alphabet.indexOf(ch);
    if (i < 0) throw new Error(`Invalid base32 char: ${ch}`);
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}
