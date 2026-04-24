// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Flametrench v0.1 identity entity types. Mirror spec/docs/identity.md
 * and spec/openapi/flametrench-v0.1.yaml shapes; camelCase in JS land.
 */

export type UsrId = `usr_${string}`;
export type CredId = `cred_${string}`;
export type SesId = `ses_${string}`;

export type Status = "active" | "suspended" | "revoked";

export type CredentialType = "password" | "passkey" | "oidc";

// ─── User ───

export interface User {
  id: UsrId;
  status: Status;
  createdAt: Date;
  updatedAt: Date;
}

// ─── Credentials (discriminated union on `type`) ───

export interface PasswordCredential {
  id: CredId;
  usrId: UsrId;
  type: "password";
  /** Login handle, typically an email. */
  identifier: string;
  status: Status;
  replaces: CredId | null;
  createdAt: Date;
  updatedAt: Date;
  // NOTE: passwordHash is intentionally NOT part of the public Credential
  // shape. Verification uses the verifyPassword operation instead of
  // exposing the hash material to callers.
}

export interface PasskeyCredential {
  id: CredId;
  usrId: UsrId;
  type: "passkey";
  /** WebAuthn credential ID (base64url-encoded). */
  identifier: string;
  status: Status;
  replaces: CredId | null;
  /** WebAuthn signature counter. Incremented on each successful assertion. */
  passkeySignCount: number;
  /** Relying party ID (typically the application's eTLD+1). */
  passkeyRpId: string;
  createdAt: Date;
  updatedAt: Date;
  // NOTE: passkeyPublicKey bytes are internal. Verification of assertions
  // is the application's responsibility in v0.0.1; an SDK-level WebAuthn
  // verifier is planned for v0.2+.
}

export interface OidcCredential {
  id: CredId;
  usrId: UsrId;
  type: "oidc";
  identifier: string;
  status: Status;
  replaces: CredId | null;
  oidcIssuer: string;
  oidcSubject: string;
  createdAt: Date;
  updatedAt: Date;
}

/** Public union — safe to expose to callers. Excludes sensitive material. */
export type Credential =
  | PasswordCredential
  | PasskeyCredential
  | OidcCredential;

// ─── Session ───

export interface Session {
  id: SesId;
  usrId: UsrId;
  credId: CredId;
  createdAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
}

// ─── Operation inputs ───

export interface CreatePasswordCredentialInput {
  usrId: UsrId;
  type: "password";
  identifier: string;
  /** Plaintext password. Hashed server-side per the spec's Argon2id pin. */
  password: string;
}

export interface CreatePasskeyCredentialInput {
  usrId: UsrId;
  type: "passkey";
  identifier: string;
  /** Raw WebAuthn public key bytes (COSE-encoded). */
  publicKey: Uint8Array;
  signCount: number;
  rpId: string;
}

export interface CreateOidcCredentialInput {
  usrId: UsrId;
  type: "oidc";
  identifier: string;
  oidcIssuer: string;
  oidcSubject: string;
}

export type CreateCredentialInput =
  | CreatePasswordCredentialInput
  | CreatePasskeyCredentialInput
  | CreateOidcCredentialInput;

export interface RotatePasswordInput {
  credId: CredId;
  type: "password";
  newPassword: string;
}

export interface RotatePasskeyInput {
  credId: CredId;
  type: "passkey";
  publicKey: Uint8Array;
  signCount: number;
  rpId: string;
}

export interface RotateOidcInput {
  credId: CredId;
  type: "oidc";
  oidcIssuer: string;
  oidcSubject: string;
}

export type RotateCredentialInput =
  | RotatePasswordInput
  | RotatePasskeyInput
  | RotateOidcInput;

export interface VerifyPasswordInput {
  /** Credential type — MUST be "password" for this operation. */
  type: "password";
  identifier: string;
  password: string;
}

export interface VerifiedCredentialResult {
  usrId: UsrId;
  credId: CredId;
}

export interface FindCredentialInput {
  type: CredentialType;
  identifier: string;
}

export interface CreateSessionInput {
  usrId: UsrId;
  credId: CredId;
  /** Session lifetime in seconds. Implementations MAY cap the upper bound. */
  ttlSeconds: number;
}

export interface CreateSessionResult {
  session: Session;
  /**
   * Opaque bearer token. The caller passes this in Authorization: Bearer;
   * the session id (`session.id`) is NOT the token.
   */
  token: string;
}

export interface ListOptions {
  cursor?: string;
  limit?: number;
}

export interface Page<T> {
  data: T[];
  nextCursor: string | null;
}

// ─── Argon2id parameter floors (spec-required) ───

/**
 * The spec's minimum Argon2id parameters for password hashing. Implementations
 * MUST use values at or above these. See spec/docs/identity.md §"Hashing
 * requirements" and ADR 0004.
 */
export const ARGON2ID_FLOOR = {
  memoryCost: 19456, // KiB (= 19 MiB)
  timeCost: 2,
  parallelism: 1,
} as const;
