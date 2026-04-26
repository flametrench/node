// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for v0.2 WebAuthn primitives. Cross-SDK parity is enforced
// by the conformance corpus; these tests cover the in-SDK pieces the
// fixtures don't pin (error code shape, COSE-key edge cases).

import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  sign as cryptoSign,
} from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  WebAuthnChallengeMismatchError,
  WebAuthnCounterRegressionError,
  WebAuthnError,
  WebAuthnMalformedError,
  WebAuthnOriginMismatchError,
  WebAuthnRpIdMismatchError,
  WebAuthnSignatureError,
  WebAuthnTypeMismatchError,
  WebAuthnUnsupportedKeyError,
  WebAuthnUserNotPresentError,
  WebAuthnUserNotVerifiedError,
  b64urlEncode,
  coseKeyEs256,
  webauthnVerifyAssertion,
} from "../src/index.js";

const RP_ID = "test.example";
const ORIGIN = "https://test.example";
const CHALLENGE = new TextEncoder().encode("unit-test-challenge");

function buildKeypair(): { privateKey: ReturnType<typeof createPrivateKey>; cose: Uint8Array } {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");
  return { privateKey, cose: coseKeyEs256(x, y) };
}

function makeAuthData(opts: { rpId?: string; flags?: number; signCount?: number } = {}): Uint8Array {
  const { rpId = RP_ID, flags = 0x05, signCount = 1 } = opts;
  const out = Buffer.alloc(37);
  createHash("sha256").update(rpId, "utf-8").digest().copy(out, 0);
  out[32] = flags;
  out.writeUInt32BE(signCount, 33);
  return out;
}

function makeClientData(opts: { challenge?: Uint8Array; origin?: string; type?: string } = {}): Uint8Array {
  const { challenge = CHALLENGE, origin = ORIGIN, type = "webauthn.get" } = opts;
  const obj = { challenge: b64urlEncode(challenge), origin, type };
  // Sort keys for byte-stability (matches Python's sort_keys=True).
  return Buffer.from(JSON.stringify(obj));
}

function signMessage(privateKey: ReturnType<typeof createPrivateKey>, authData: Uint8Array, clientData: Uint8Array): Uint8Array {
  const clientHash = createHash("sha256").update(clientData).digest();
  return cryptoSign("sha256", Buffer.concat([authData, clientHash]), {
    key: privateKey,
    dsaEncoding: "der",
  });
}

describe("webauthnVerifyAssertion", () => {
  it("verifies a well-formed assertion and returns the new count", () => {
    const { privateKey, cose } = buildKeypair();
    const auth = makeAuthData({ signCount: 42 });
    const client = makeClientData();
    const sig = signMessage(privateKey, auth, client);
    const result = webauthnVerifyAssertion({
      cosePublicKey: cose,
      storedSignCount: 10,
      storedRpId: RP_ID,
      expectedChallenge: CHALLENGE,
      expectedOrigin: ORIGIN,
      authenticatorData: auth,
      clientDataJson: client,
      signature: sig,
    });
    expect(result.newSignCount).toBe(42);
  });

  it("accepts both-zero counter (authenticator does not track)", () => {
    const { privateKey, cose } = buildKeypair();
    const auth = makeAuthData({ signCount: 0 });
    const client = makeClientData();
    const sig = signMessage(privateKey, auth, client);
    const result = webauthnVerifyAssertion({
      cosePublicKey: cose,
      storedSignCount: 0,
      storedRpId: RP_ID,
      expectedChallenge: CHALLENGE,
      expectedOrigin: ORIGIN,
      authenticatorData: auth,
      clientDataJson: client,
      signature: sig,
    });
    expect(result.newSignCount).toBe(0);
  });

  it("rejects equal counter (cloned-authenticator signal)", () => {
    const { privateKey, cose } = buildKeypair();
    const auth = makeAuthData({ signCount: 10 });
    const client = makeClientData();
    const sig = signMessage(privateKey, auth, client);
    expect(() =>
      webauthnVerifyAssertion({
        cosePublicKey: cose,
        storedSignCount: 10,
        storedRpId: RP_ID,
        expectedChallenge: CHALLENGE,
        expectedOrigin: ORIGIN,
        authenticatorData: auth,
        clientDataJson: client,
        signature: sig,
      }),
    ).toThrow(WebAuthnCounterRegressionError);
  });

  it("rejects assertion missing UV flag by default", () => {
    const { privateKey, cose } = buildKeypair();
    const auth = makeAuthData({ flags: 0x01, signCount: 2 });
    const client = makeClientData();
    const sig = signMessage(privateKey, auth, client);
    expect(() =>
      webauthnVerifyAssertion({
        cosePublicKey: cose,
        storedSignCount: 1,
        storedRpId: RP_ID,
        expectedChallenge: CHALLENGE,
        expectedOrigin: ORIGIN,
        authenticatorData: auth,
        clientDataJson: client,
        signature: sig,
      }),
    ).toThrow(WebAuthnUserNotVerifiedError);
  });

  it("rejects assertion missing UP flag by default", () => {
    const { privateKey, cose } = buildKeypair();
    const auth = makeAuthData({ flags: 0x04, signCount: 2 });
    const client = makeClientData();
    const sig = signMessage(privateKey, auth, client);
    expect(() =>
      webauthnVerifyAssertion({
        cosePublicKey: cose,
        storedSignCount: 1,
        storedRpId: RP_ID,
        expectedChallenge: CHALLENGE,
        expectedOrigin: ORIGIN,
        authenticatorData: auth,
        clientDataJson: client,
        signature: sig,
      }),
    ).toThrow(WebAuthnUserNotPresentError);
  });

  it("can disable UV requirement for legacy 2FA", () => {
    const { privateKey, cose } = buildKeypair();
    const auth = makeAuthData({ flags: 0x01, signCount: 2 });
    const client = makeClientData();
    const sig = signMessage(privateKey, auth, client);
    const result = webauthnVerifyAssertion({
      cosePublicKey: cose,
      storedSignCount: 1,
      storedRpId: RP_ID,
      expectedChallenge: CHALLENGE,
      expectedOrigin: ORIGIN,
      authenticatorData: auth,
      clientDataJson: client,
      signature: sig,
      requireUserVerified: false,
    });
    expect(result.newSignCount).toBe(2);
  });

  it("rejects RP ID mismatch", () => {
    const { privateKey, cose } = buildKeypair();
    const auth = makeAuthData({ rpId: "evil.test", signCount: 2 });
    const client = makeClientData();
    const sig = signMessage(privateKey, auth, client);
    expect(() =>
      webauthnVerifyAssertion({
        cosePublicKey: cose,
        storedSignCount: 1,
        storedRpId: RP_ID,
        expectedChallenge: CHALLENGE,
        expectedOrigin: ORIGIN,
        authenticatorData: auth,
        clientDataJson: client,
        signature: sig,
      }),
    ).toThrow(WebAuthnRpIdMismatchError);
  });

  it("rejects origin mismatch", () => {
    const { privateKey, cose } = buildKeypair();
    const auth = makeAuthData({ signCount: 2 });
    const client = makeClientData({ origin: "https://evil.test" });
    const sig = signMessage(privateKey, auth, client);
    expect(() =>
      webauthnVerifyAssertion({
        cosePublicKey: cose,
        storedSignCount: 1,
        storedRpId: RP_ID,
        expectedChallenge: CHALLENGE,
        expectedOrigin: ORIGIN,
        authenticatorData: auth,
        clientDataJson: client,
        signature: sig,
      }),
    ).toThrow(WebAuthnOriginMismatchError);
  });

  it("rejects challenge mismatch", () => {
    const { privateKey, cose } = buildKeypair();
    const auth = makeAuthData({ signCount: 2 });
    const client = makeClientData({ challenge: new TextEncoder().encode("different") });
    const sig = signMessage(privateKey, auth, client);
    expect(() =>
      webauthnVerifyAssertion({
        cosePublicKey: cose,
        storedSignCount: 1,
        storedRpId: RP_ID,
        expectedChallenge: CHALLENGE,
        expectedOrigin: ORIGIN,
        authenticatorData: auth,
        clientDataJson: client,
        signature: sig,
      }),
    ).toThrow(WebAuthnChallengeMismatchError);
  });

  it("rejects type other than webauthn.get", () => {
    const { privateKey, cose } = buildKeypair();
    const auth = makeAuthData({ signCount: 2 });
    const client = makeClientData({ type: "webauthn.create" });
    const sig = signMessage(privateKey, auth, client);
    expect(() =>
      webauthnVerifyAssertion({
        cosePublicKey: cose,
        storedSignCount: 1,
        storedRpId: RP_ID,
        expectedChallenge: CHALLENGE,
        expectedOrigin: ORIGIN,
        authenticatorData: auth,
        clientDataJson: client,
        signature: sig,
      }),
    ).toThrow(WebAuthnTypeMismatchError);
  });

  it("rejects tampered signature", () => {
    const { privateKey, cose } = buildKeypair();
    const auth = makeAuthData({ signCount: 2 });
    const client = makeClientData();
    const sig = Buffer.from(signMessage(privateKey, auth, client));
    sig[sig.length - 1] ^= 0x01;
    expect(() =>
      webauthnVerifyAssertion({
        cosePublicKey: cose,
        storedSignCount: 1,
        storedRpId: RP_ID,
        expectedChallenge: CHALLENGE,
        expectedOrigin: ORIGIN,
        authenticatorData: auth,
        clientDataJson: client,
        signature: sig,
      }),
    ).toThrow(WebAuthnSignatureError);
  });

  it("rejects truncated authenticatorData", () => {
    const { cose } = buildKeypair();
    expect(() =>
      webauthnVerifyAssertion({
        cosePublicKey: cose,
        storedSignCount: 0,
        storedRpId: RP_ID,
        expectedChallenge: CHALLENGE,
        expectedOrigin: ORIGIN,
        authenticatorData: new Uint8Array(10),
        clientDataJson: makeClientData(),
        signature: Buffer.from("3006020101020101", "hex"),
      }),
    ).toThrow(WebAuthnMalformedError);
  });

  it("rejects malformed clientDataJSON", () => {
    const { cose } = buildKeypair();
    expect(() =>
      webauthnVerifyAssertion({
        cosePublicKey: cose,
        storedSignCount: 0,
        storedRpId: RP_ID,
        expectedChallenge: CHALLENGE,
        expectedOrigin: ORIGIN,
        authenticatorData: makeAuthData(),
        clientDataJson: Buffer.from("not json"),
        signature: Buffer.from("3006020101020101", "hex"),
      }),
    ).toThrow(WebAuthnMalformedError);
  });

  it("rejects unsupported COSE kty (OKP / kty=1)", () => {
    // OKP key with all-zero coordinates — structurally legal CBOR, semantically
    // not what v0.2 supports.
    const bad = Buffer.concat([
      Buffer.from([0xa5, 0x01, 0x01, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
      Buffer.alloc(32),
      Buffer.from([0x22, 0x58, 0x20]),
      Buffer.alloc(32),
    ]);
    expect(() =>
      webauthnVerifyAssertion({
        cosePublicKey: bad,
        storedSignCount: 0,
        storedRpId: RP_ID,
        expectedChallenge: CHALLENGE,
        expectedOrigin: ORIGIN,
        authenticatorData: makeAuthData(),
        clientDataJson: makeClientData(),
        signature: Buffer.from("3006020101020101", "hex"),
      }),
    ).toThrow(WebAuthnUnsupportedKeyError);
  });

  it("error codes carry the webauthn prefix", () => {
    const err = new WebAuthnSignatureError();
    expect(err.code).toBe("webauthn.signature_invalid");
    expect(err).toBeInstanceOf(WebAuthnError);
  });
});
