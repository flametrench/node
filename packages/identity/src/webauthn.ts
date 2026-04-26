// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * WebAuthn assertion verification — v0.2 reference per ADR 0008.
 *
 * Mirrors identity-python's webauthn.py exactly so the conformance
 * fixture corpus passes byte-identically across SDKs.
 *
 * Scope (v0.2): ES256 (ECDSA P-256 + SHA-256) only. RS256 and EdDSA
 * are deferred to v0.3.
 */

import {
  createHash,
  createPublicKey,
  verify as cryptoVerify,
} from "node:crypto";

import { IdentityError } from "./errors.js";

// ─── Errors ──────────────────────────────────────────────────────

export class WebAuthnError extends IdentityError {
  constructor(
    message: string,
    public readonly reason: WebAuthnFailureReason,
  ) {
    super(message, `webauthn.${reason}`);
    this.name = "WebAuthnError";
  }
}

export type WebAuthnFailureReason =
  | "signature_invalid"
  | "counter_regression"
  | "rp_id_mismatch"
  | "user_not_verified"
  | "user_not_present"
  | "challenge_mismatch"
  | "origin_mismatch"
  | "type_mismatch"
  | "malformed"
  | "unsupported_key";

export class WebAuthnSignatureError extends WebAuthnError {
  constructor(message = "Signature verification failed") {
    super(message, "signature_invalid");
    this.name = "WebAuthnSignatureError";
  }
}

export class WebAuthnCounterRegressionError extends WebAuthnError {
  constructor(message = "Sign count did not advance") {
    super(message, "counter_regression");
    this.name = "WebAuthnCounterRegressionError";
  }
}

export class WebAuthnRpIdMismatchError extends WebAuthnError {
  constructor(message = "RP ID hash mismatch") {
    super(message, "rp_id_mismatch");
    this.name = "WebAuthnRpIdMismatchError";
  }
}

export class WebAuthnUserNotVerifiedError extends WebAuthnError {
  constructor(message = "User-verified flag not set") {
    super(message, "user_not_verified");
    this.name = "WebAuthnUserNotVerifiedError";
  }
}

export class WebAuthnUserNotPresentError extends WebAuthnError {
  constructor(message = "User-present flag not set") {
    super(message, "user_not_present");
    this.name = "WebAuthnUserNotPresentError";
  }
}

export class WebAuthnChallengeMismatchError extends WebAuthnError {
  constructor(message = "Challenge mismatch") {
    super(message, "challenge_mismatch");
    this.name = "WebAuthnChallengeMismatchError";
  }
}

export class WebAuthnOriginMismatchError extends WebAuthnError {
  constructor(message = "Origin mismatch") {
    super(message, "origin_mismatch");
    this.name = "WebAuthnOriginMismatchError";
  }
}

export class WebAuthnTypeMismatchError extends WebAuthnError {
  constructor(message = "Type mismatch") {
    super(message, "type_mismatch");
    this.name = "WebAuthnTypeMismatchError";
  }
}

export class WebAuthnMalformedError extends WebAuthnError {
  constructor(message = "Malformed assertion input") {
    super(message, "malformed");
    this.name = "WebAuthnMalformedError";
  }
}

export class WebAuthnUnsupportedKeyError extends WebAuthnError {
  constructor(message = "Unsupported COSE key") {
    super(message, "unsupported_key");
    this.name = "WebAuthnUnsupportedKeyError";
  }
}

// ─── Result ──────────────────────────────────────────────────────

export interface WebAuthnAssertionResult {
  newSignCount: number;
}

// ─── Authenticator data flag bits ────────────────────────────────

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;

// ─── Minimal CBOR / COSE-key parsing ─────────────────────────────

interface CborDecoder {
  buf: Uint8Array;
  offset: number;
}

function readBytes(d: CborDecoder, n: number): Uint8Array {
  if (d.offset + n > d.buf.length) {
    throw new WebAuthnMalformedError("CBOR truncated");
  }
  const out = d.buf.subarray(d.offset, d.offset + n);
  d.offset += n;
  return out;
}

function readUint(d: CborDecoder, info: number): number {
  if (info < 24) return info;
  if (info === 24) {
    return readBytes(d, 1)[0]!;
  }
  if (info === 25) {
    const b = readBytes(d, 2);
    return new DataView(b.buffer, b.byteOffset, 2).getUint16(0, false);
  }
  if (info === 26) {
    const b = readBytes(d, 4);
    return new DataView(b.buffer, b.byteOffset, 4).getUint32(0, false);
  }
  if (info === 27) {
    // 64-bit lengths are unrealistic for COSE keys; reject for safety.
    throw new WebAuthnMalformedError("CBOR 64-bit lengths unsupported");
  }
  throw new WebAuthnMalformedError(`Unsupported CBOR info: ${info}`);
}

function decodeItem(d: CborDecoder): unknown {
  const first = readBytes(d, 1)[0]!;
  const major = first >> 5;
  const info = first & 0x1f;
  if (major === 0) return readUint(d, info);
  if (major === 1) return -1 - readUint(d, info);
  if (major === 2) {
    const length = readUint(d, info);
    return readBytes(d, length);
  }
  if (major === 5) {
    const length = readUint(d, info);
    const out = new Map<number, unknown>();
    for (let i = 0; i < length; i++) {
      const key = decodeItem(d);
      const value = decodeItem(d);
      if (typeof key !== "number") {
        throw new WebAuthnMalformedError("Non-int CBOR map key");
      }
      out.set(key, value);
    }
    return out;
  }
  throw new WebAuthnMalformedError(`Unsupported CBOR major type: ${major}`);
}

/** Minimum RSA modulus per ADR 0010 / WebAuthn §5.8.5. */
const RSA_MIN_KEY_SIZE_BITS = 2048;

/** COSE alg values (RFC 8152 §13). */
type CoseAlg = -7 | -257 | -8;

interface CoseEs256 {
  alg: -7;
  x: Uint8Array;
  y: Uint8Array;
}
interface CoseRs256 {
  alg: -257;
  n: Uint8Array;
  e: Uint8Array;
}
interface CoseEddsa {
  alg: -8;
  x: Uint8Array;
}
type ParsedCose = CoseEs256 | CoseRs256 | CoseEddsa;

function parseCoseKey(coseKey: Uint8Array): ParsedCose {
  const d: CborDecoder = { buf: coseKey, offset: 0 };
  const value = decodeItem(d);
  if (d.offset !== coseKey.length) {
    throw new WebAuthnMalformedError("Trailing bytes after CBOR map");
  }
  if (!(value instanceof Map)) {
    throw new WebAuthnMalformedError("Top-level COSE value is not a map");
  }
  const kty = value.get(1);
  const alg = value.get(3);
  if (alg === -7) {
    if (kty !== 2) {
      throw new WebAuthnUnsupportedKeyError(`ES256 requires COSE kty=2, got ${String(kty)}`);
    }
    const crv = value.get(-1);
    const x = value.get(-2);
    const y = value.get(-3);
    if (crv !== 1) {
      throw new WebAuthnUnsupportedKeyError(`ES256 requires crv=1, got ${String(crv)}`);
    }
    if (!(x instanceof Uint8Array) || x.length !== 32) {
      throw new WebAuthnMalformedError("COSE x coordinate must be 32 bytes");
    }
    if (!(y instanceof Uint8Array) || y.length !== 32) {
      throw new WebAuthnMalformedError("COSE y coordinate must be 32 bytes");
    }
    return { alg: -7, x, y };
  }
  if (alg === -257) {
    if (kty !== 3) {
      throw new WebAuthnUnsupportedKeyError(`RS256 requires COSE kty=3, got ${String(kty)}`);
    }
    const n = value.get(-1);
    const e = value.get(-2);
    if (!(n instanceof Uint8Array)) {
      throw new WebAuthnMalformedError("COSE RSA modulus (n) must be a byte string");
    }
    if (!(e instanceof Uint8Array)) {
      throw new WebAuthnMalformedError("COSE RSA exponent (e) must be a byte string");
    }
    // Strip a single leading 0x00 (CBOR positive-int convention) so
    // bit-length is computed on the value, not the encoding.
    const nTrimmed = n.length > 0 && n[0] === 0 ? n.subarray(1) : n;
    const bits = nTrimmed.length * 8 - leadingZeroBits(nTrimmed);
    if (bits < RSA_MIN_KEY_SIZE_BITS) {
      throw new WebAuthnUnsupportedKeyError(
        `RSA key ${bits}-bit is below the ${RSA_MIN_KEY_SIZE_BITS}-bit floor`,
      );
    }
    return { alg: -257, n, e };
  }
  if (alg === -8) {
    if (kty !== 1) {
      throw new WebAuthnUnsupportedKeyError(`EdDSA requires COSE kty=1, got ${String(kty)}`);
    }
    const crv = value.get(-1);
    const x = value.get(-2);
    if (crv !== 6) {
      throw new WebAuthnUnsupportedKeyError(
        `v0.2 EdDSA accepts only Ed25519 (crv=6), got crv=${String(crv)}`,
      );
    }
    if (!(x instanceof Uint8Array) || x.length !== 32) {
      throw new WebAuthnMalformedError("Ed25519 public key must be 32 bytes");
    }
    return { alg: -8, x };
  }
  throw new WebAuthnUnsupportedKeyError(
    `Unsupported COSE alg: ${String(alg)} (kty=${String(kty)})`,
  );
}

/** Count leading zero bits of the most-significant byte in a big-endian unsigned int. */
function leadingZeroBits(buf: Uint8Array): number {
  if (buf.length === 0) return 0;
  let b = buf[0]!;
  if (b === 0) return 8;
  let n = 0;
  while ((b & 0x80) === 0) {
    b <<= 1;
    n++;
  }
  return n;
}

// ─── Authenticator data ──────────────────────────────────────────

interface AuthenticatorData {
  rpIdHash: Uint8Array;
  flags: number;
  signCount: number;
}

function parseAuthenticatorData(buf: Uint8Array): AuthenticatorData {
  if (buf.length < 37) {
    throw new WebAuthnMalformedError("authenticatorData truncated");
  }
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  return {
    rpIdHash: buf.subarray(0, 32),
    flags: buf[32]!,
    signCount: view.getUint32(33, false),
  };
}

// ─── Helpers ─────────────────────────────────────────────────────

/** Encode bytes as base64url with no padding (WebAuthn convention). */
export function b64urlEncode(buf: Uint8Array): string {
  return Buffer.from(buf).toString("base64url");
}

function b64urlDecode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * Build a COSE_Key (RFC 8152) for an ES256 / P-256 public key from raw
 * 32-byte x/y coordinates. Inverse of the ES256 path through
 * `parseCoseEs256`.
 */
export function coseKeyEs256(x: Uint8Array, y: Uint8Array): Uint8Array {
  if (x.length !== 32 || y.length !== 32) {
    throw new Error("ES256 coordinates must be 32 bytes each");
  }
  // 1 (map header) + 2 (kty) + 2 (alg) + 2 (crv) + 3 (-2 hdr) + 32 (x)
  // + 3 (-3 hdr) + 32 (y) = 77.
  const out = new Uint8Array(1 + 2 + 2 + 2 + 3 + 32 + 3 + 32);
  let off = 0;
  out[off++] = 0xa5; // map(5)
  out[off++] = 0x01;
  out[off++] = 0x02; // 1: 2
  out[off++] = 0x03;
  out[off++] = 0x26; // 3: -7
  out[off++] = 0x20;
  out[off++] = 0x01; // -1: 1
  out[off++] = 0x21;
  out[off++] = 0x58;
  out[off++] = 0x20;
  out.set(x, off);
  off += 32;
  out[off++] = 0x22;
  out[off++] = 0x58;
  out[off++] = 0x20;
  out.set(y, off);
  return out;
}

// ─── Public verifier ─────────────────────────────────────────────

export interface VerifyAssertionInput {
  /** COSE_Key bytes from credential registration. v0.2 supports ES256 only. */
  cosePublicKey: Uint8Array;
  /** Signature counter recorded on the last successful assertion (or registration). */
  storedSignCount: number;
  /** RP ID the credential was registered for. */
  storedRpId: string;
  /** Raw challenge bytes the application issued for this assertion. */
  expectedChallenge: Uint8Array;
  /** Origin the application expects (e.g. "https://example.com"). */
  expectedOrigin: string;
  /** AuthenticatorAssertionResponse.authenticatorData bytes. */
  authenticatorData: Uint8Array;
  /** AuthenticatorAssertionResponse.clientDataJSON bytes (raw). */
  clientDataJson: Uint8Array;
  /** AuthenticatorAssertionResponse.signature bytes (DER ECDSA for ES256). */
  signature: Uint8Array;
  /** When true (default), reject assertions that lack the UV bit. */
  requireUserVerified?: boolean;
  /** When true (default), reject assertions that lack the UP bit. */
  requireUserPresent?: boolean;
}

/**
 * Verify a WebAuthn assertion and return the new sign count.
 *
 * @throws {WebAuthnError} subclass per failure mode.
 */
export function webauthnVerifyAssertion(
  input: VerifyAssertionInput,
): WebAuthnAssertionResult {
  const requireUv = input.requireUserVerified ?? true;
  const requireUp = input.requireUserPresent ?? true;

  // Parse clientDataJSON.
  let clientData: unknown;
  try {
    clientData = JSON.parse(Buffer.from(input.clientDataJson).toString("utf-8"));
  } catch (err) {
    throw new WebAuthnMalformedError(
      `clientDataJSON not valid JSON: ${(err as Error).message}`,
    );
  }
  if (
    typeof clientData !== "object" ||
    clientData === null ||
    Array.isArray(clientData)
  ) {
    throw new WebAuthnMalformedError("clientDataJSON is not an object");
  }
  const cd = clientData as Record<string, unknown>;
  if (cd.type !== "webauthn.get") {
    throw new WebAuthnTypeMismatchError(
      `clientDataJSON.type must be 'webauthn.get', got ${JSON.stringify(cd.type)}`,
    );
  }
  if (cd.origin !== input.expectedOrigin) {
    throw new WebAuthnOriginMismatchError(
      `Origin mismatch: expected ${input.expectedOrigin}, got ${String(cd.origin)}`,
    );
  }
  if (typeof cd.challenge !== "string") {
    throw new WebAuthnMalformedError(
      "clientDataJSON.challenge missing or not a string",
    );
  }
  let challengeBytes: Uint8Array;
  try {
    challengeBytes = b64urlDecode(cd.challenge);
  } catch (err) {
    throw new WebAuthnMalformedError(
      `clientDataJSON.challenge not base64url: ${(err as Error).message}`,
    );
  }
  if (!timingSafeEqualBytes(challengeBytes, input.expectedChallenge)) {
    throw new WebAuthnChallengeMismatchError("Challenge does not match");
  }

  // Parse authenticatorData and check RP-ID + flags + counter.
  const auth = parseAuthenticatorData(input.authenticatorData);
  const expectedRpHash = createHash("sha256")
    .update(input.storedRpId, "utf-8")
    .digest();
  if (!timingSafeEqualBytes(auth.rpIdHash, expectedRpHash)) {
    throw new WebAuthnRpIdMismatchError("RP ID hash does not match");
  }
  if (requireUp && (auth.flags & FLAG_UP) === 0) {
    throw new WebAuthnUserNotPresentError();
  }
  if (requireUv && (auth.flags & FLAG_UV) === 0) {
    throw new WebAuthnUserNotVerifiedError();
  }

  // Counter monotonicity (WebAuthn §6.1.1).
  let newSignCount: number;
  if (auth.signCount === 0 && input.storedSignCount === 0) {
    newSignCount = 0;
  } else if (auth.signCount > input.storedSignCount) {
    newSignCount = auth.signCount;
  } else {
    throw new WebAuthnCounterRegressionError(
      `Sign count did not advance: stored=${input.storedSignCount}, got=${auth.signCount}`,
    );
  }

  // Verify the signature over authData || sha256(clientDataJSON).
  // Algorithm dispatch per ADR 0010: COSE_Key.alg picks the verifier.
  const cose = parseCoseKey(input.cosePublicKey);
  const clientHash = createHash("sha256").update(input.clientDataJson).digest();
  const signed = Buffer.concat([
    Buffer.from(input.authenticatorData),
    clientHash,
  ]);

  let ok: boolean;
  try {
    if (cose.alg === -7) {
      // ES256 — DER-encoded ECDSA signature.
      if (input.signature.length < 8 || input.signature[0]! !== 0x30) {
        throw new WebAuthnSignatureError("Signature is not a DER ECDSA structure");
      }
      const publicKey = createPublicKey({
        key: { kty: "EC", crv: "P-256", x: b64urlEncode(cose.x), y: b64urlEncode(cose.y) },
        format: "jwk",
      });
      ok = cryptoVerify(
        "sha256",
        signed,
        { key: publicKey, dsaEncoding: "der" },
        Buffer.from(input.signature),
      );
    } else if (cose.alg === -257) {
      // RS256 — raw RSASSA-PKCS1-v1_5 signature.
      const publicKey = createPublicKey({
        key: { kty: "RSA", n: b64urlEncode(stripLeadingZero(cose.n)), e: b64urlEncode(stripLeadingZero(cose.e)) },
        format: "jwk",
      });
      ok = cryptoVerify("sha256", signed, publicKey, Buffer.from(input.signature));
    } else {
      // EdDSA / Ed25519 — 64 raw bytes; pass `null` algorithm to crypto.verify.
      if (input.signature.length !== 64) {
        throw new WebAuthnSignatureError(
          `Ed25519 signature must be 64 bytes, got ${input.signature.length}`,
        );
      }
      const publicKey = createPublicKey({
        key: { kty: "OKP", crv: "Ed25519", x: b64urlEncode(cose.x) },
        format: "jwk",
      });
      ok = cryptoVerify(null, signed, publicKey, Buffer.from(input.signature));
    }
  } catch (err) {
    if (err instanceof WebAuthnError) throw err;
    // node:crypto throws on malformed DER (tampered length byte) or
    // structurally-invalid signatures. Treat identically to a verify-
    // returns-false case.
    throw new WebAuthnSignatureError(
      `Signature verification threw: ${(err as Error).message}`,
    );
  }
  if (!ok) {
    throw new WebAuthnSignatureError();
  }

  return { newSignCount };
}

/** Strip a single leading 0x00 from an unsigned big-endian integer encoding. */
function stripLeadingZero(buf: Uint8Array): Uint8Array {
  return buf.length > 0 && buf[0] === 0 ? buf.subarray(1) : buf;
}
