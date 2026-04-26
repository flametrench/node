// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Multi-factor authentication primitives — v0.2 reference per ADR 0008.
 *
 * Three first-class factor types:
 *   - TOTP (RFC 6238) — 30-second window, 6-digit codes by default,
 *     HMAC-SHA1 / HMAC-SHA256 / HMAC-SHA512 supported.
 *   - Recovery codes — 10 single-use codes; format predicate exposed.
 *   - WebAuthn — factor records supported (full assertion verification
 *     deferred to a follow-up commit).
 *
 * The `mfa_` ID prefix is registered in v0.2 (ADR 0008). Until v0.2
 * ships, this module is non-normative reference code.
 */

import { createHmac, randomInt, timingSafeEqual } from "node:crypto";

// ─── Factor types ───

export type FactorType = "totp" | "webauthn" | "recovery";

export type FactorStatus = "pending" | "active" | "suspended" | "revoked";

// ─── Public factor records (sensitive payload stripped) ───

export interface TotpFactor {
  type: "totp";
  id: string;
  usrId: string;
  identifier: string; // human-readable label
  status: FactorStatus;
  replaces: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface WebAuthnFactor {
  type: "webauthn";
  id: string;
  usrId: string;
  identifier: string; // WebAuthn credential ID, base64url-encoded
  status: FactorStatus;
  replaces: string | null;
  rpId: string;
  signCount: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface RecoveryFactor {
  type: "recovery";
  id: string;
  usrId: string;
  status: FactorStatus;
  replaces: string | null;
  createdAt: Date;
  updatedAt: Date;
  /** Number of unconsumed codes remaining; hashes are internal. */
  remaining: number;
  identifier?: string;
}

export type Factor = TotpFactor | WebAuthnFactor | RecoveryFactor;

// ─── User MFA policy ───

export interface UserMfaPolicy {
  usrId: string;
  required: boolean;
  graceUntil: Date | null;
  updatedAt: Date;
}

/** True when MFA enforcement is active for this user as of `now`. */
export function isMfaPolicyActiveNow(
  policy: UserMfaPolicy,
  now: Date = new Date(),
): boolean {
  if (!policy.required) return false;
  if (policy.graceUntil === null) return true;
  return now >= policy.graceUntil;
}

// ─── TOTP (RFC 6238) ───

export const DEFAULT_TOTP_PERIOD = 30;
export const DEFAULT_TOTP_DIGITS = 6;
export type TotpAlgorithm = "sha1" | "sha256" | "sha512";
export const DEFAULT_TOTP_ALGORITHM: TotpAlgorithm = "sha1";

interface TotpOptions {
  period?: number;
  digits?: number;
  algorithm?: TotpAlgorithm;
}

/**
 * Compute the TOTP code for a given secret and timestamp.
 *
 * Implements the RFC 6238 / RFC 4226 dynamic-truncation algorithm
 * directly. Cross-SDK byte-identical because the algorithm is
 * deterministic and exhaustively spec'd.
 *
 * @param secret Raw shared-secret bytes (NOT base32-encoded).
 * @param timestamp Unix seconds at which to compute the code.
 */
export function totpCompute(
  secret: Uint8Array,
  timestamp: number,
  options: TotpOptions = {},
): string {
  const period = options.period ?? DEFAULT_TOTP_PERIOD;
  const digits = options.digits ?? DEFAULT_TOTP_DIGITS;
  const algorithm = options.algorithm ?? DEFAULT_TOTP_ALGORITHM;

  const counter = Math.floor(timestamp / period);
  // Big-endian 8-byte counter. JS Number safely represents up to 2^53,
  // which is well beyond 2038-problem timescales — no BigInt needed
  // for spec-floor inputs. For paranoia we still pack as two 32-bit
  // halves so the high 21 bits don't get mishandled.
  const counterBytes = Buffer.alloc(8);
  counterBytes.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBytes.writeUInt32BE(counter >>> 0, 4);

  const digest = createHmac(algorithm, Buffer.from(secret))
    .update(counterBytes)
    .digest();

  const offset = digest[digest.length - 1]! & 0x0f;
  const codeInt =
    (((digest[offset]! & 0x7f) << 24) |
      ((digest[offset + 1]! & 0xff) << 16) |
      ((digest[offset + 2]! & 0xff) << 8) |
      (digest[offset + 3]! & 0xff)) >>>
    0;

  return String(codeInt % 10 ** digits).padStart(digits, "0");
}

interface TotpVerifyOptions extends TotpOptions {
  timestamp?: number;
  driftWindows?: number;
}

/**
 * Verify a candidate TOTP code with drift tolerance.
 *
 * Accepts the code from the current window plus +/- driftWindows
 * surrounding windows (default ±1). Constant-time compared.
 *
 * Returns false on length mismatch, non-numeric input, or no match.
 */
export function totpVerify(
  secret: Uint8Array,
  candidate: string,
  options: TotpVerifyOptions = {},
): boolean {
  const period = options.period ?? DEFAULT_TOTP_PERIOD;
  const digits = options.digits ?? DEFAULT_TOTP_DIGITS;
  const algorithm = options.algorithm ?? DEFAULT_TOTP_ALGORITHM;
  const driftWindows = options.driftWindows ?? 1;
  const timestamp =
    options.timestamp ?? Math.floor(Date.now() / 1000);

  if (
    !candidate ||
    candidate.length !== digits ||
    !/^[0-9]+$/.test(candidate)
  ) {
    return false;
  }

  for (let w = -driftWindows; w <= driftWindows; w++) {
    const ts = timestamp + w * period;
    const expected = totpCompute(secret, ts, { period, digits, algorithm });
    if (
      timingSafeEqual(
        Buffer.from(expected, "ascii"),
        Buffer.from(candidate, "ascii"),
      )
    ) {
      return true;
    }
  }
  return false;
}

/** Generate a fresh TOTP shared secret. Default 20 bytes per RFC 6238. */
export function generateTotpSecret(numBytes = 20): Uint8Array {
  // Use Web Crypto for browser compatibility; node:crypto polyfills it.
  const out = new Uint8Array(numBytes);
  // randomInt is sync; loop fills the buffer one byte at a time.
  for (let i = 0; i < numBytes; i++) {
    out[i] = randomInt(0, 256);
  }
  return out;
}

interface OtpauthUriOptions {
  secret: Uint8Array;
  label: string;
  issuer: string;
  algorithm?: TotpAlgorithm;
  digits?: number;
  period?: number;
}

/** Build the otpauth:// URI for QR rendering at enrollment. */
export function totpOtpauthUri(opts: OtpauthUriOptions): string {
  const algorithm = opts.algorithm ?? DEFAULT_TOTP_ALGORITHM;
  const digits = opts.digits ?? DEFAULT_TOTP_DIGITS;
  const period = opts.period ?? DEFAULT_TOTP_PERIOD;

  // Base32 encode without padding, RFC 4648 alphabet.
  const secretB32 = base32Encode(opts.secret).replace(/=+$/, "");
  const labelQ = encodeURIComponent(`${opts.issuer}:${opts.label}`);
  const issuerQ = encodeURIComponent(opts.issuer);
  return (
    `otpauth://totp/${labelQ}` +
    `?secret=${secretB32}` +
    `&issuer=${issuerQ}` +
    `&algorithm=${algorithm.toUpperCase()}` +
    `&digits=${digits}` +
    `&period=${period}`
  );
}

/** RFC 4648 base32 encoding (with padding). */
function base32Encode(buf: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let out = "";
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i]!;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 0x1f];
  while (out.length % 8 !== 0) out += "=";
  return out;
}

// ─── Recovery codes ───

const RECOVERY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // 31 chars
export const RECOVERY_CODE_COUNT = 10;
export const RECOVERY_CODE_LENGTH = 12;

/** Generate one fresh 12-char recovery code, formatted XXXX-XXXX-XXXX. */
export function generateRecoveryCode(): string {
  const chars = Array.from({ length: RECOVERY_CODE_LENGTH }, () =>
    RECOVERY_ALPHABET.charAt(randomInt(0, RECOVERY_ALPHABET.length)),
  ).join("");
  return `${chars.slice(0, 4)}-${chars.slice(4, 8)}-${chars.slice(8, 12)}`;
}

/** Generate a fresh set of 10 recovery codes. */
export function generateRecoveryCodes(): string[] {
  return Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
}

/**
 * Normalize user-input recovery code: uppercase + strip whitespace.
 * Hyphens are preserved.
 */
export function normalizeRecoveryInput(code: string): string {
  return code.trim().toUpperCase();
}

/**
 * Predicate: does `code` match the canonical 12-char three-group form?
 *
 * True iff:
 *   - exactly 14 chars (12 alphabet + 2 hyphens)
 *   - three groups of four, hyphen-separated
 *   - every char from the recovery alphabet (excludes 0/O/1/I/L)
 *   - all chars uppercase ASCII
 */
export function isValidRecoveryCode(code: string): boolean {
  if (code.length !== RECOVERY_CODE_LENGTH + 2) return false;
  const parts = code.split("-");
  if (parts.length !== 3) return false;
  for (const part of parts) {
    if (part.length !== 4) return false;
    for (const ch of part) {
      if (!RECOVERY_ALPHABET.includes(ch)) return false;
    }
  }
  return true;
}
