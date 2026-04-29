// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * PostgresIdentityStore — Postgres-backed implementation of IdentityStore.
 *
 * Mirrors the in-memory implementation byte-for-byte at the SDK
 * boundary; the difference is durability and concurrency. Schema lives
 * in spec/reference/postgres.sql (the `usr`, `cred`, `ses`, `mfa`,
 * `usr_mfa_policy` tables). Tests vendor a snapshot of that schema and
 * gate on IDENTITY_POSTGRES_URL — see test/postgres.test.ts.
 *
 * Design notes:
 *   - All ID columns store native UUID. Wire-format prefixed IDs
 *     (`usr_<hex>`, `cred_<hex>`, ...) are computed at the SDK
 *     boundary via @flametrench/ids encode/decode.
 *   - Bearer tokens are SHA-256-hashed and stored as 32 raw bytes
 *     (BYTEA). The plaintext token is returned ONCE on create/refresh
 *     and never persisted.
 *   - Multi-statement ops (revokeUser cascade, rotateCredential,
 *     refreshSession, MFA confirm/verify) run inside a transaction so
 *     state transitions are atomic.
 *   - The natural-key partial-unique index `cred_unique_active_identifier`
 *     enforces "at most one active credential per (type, identifier)".
 *     Insert-on-conflict reads the conflicting row to surface a
 *     DuplicateCredentialError with the existing id attached.
 *   - WebAuthn factors permit multiple active per user; TOTP and
 *     recovery are constrained to one active each by
 *     `mfa_unique_active_singleton`.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import { decode, encode, generate } from "@flametrench/ids";
import argon2 from "argon2";
import type { Pool, PoolClient } from "pg";

import {
  AlreadyTerminalError,
  CredentialNotActiveError,
  CredentialTypeMismatchError,
  DuplicateCredentialError,
  InvalidCredentialError,
  InvalidTokenError,
  NotFoundError,
  PreconditionError,
  SessionExpiredError,
} from "./errors.js";
import { hashPassword, verifyPasswordHash } from "./hashing.js";
import {
  DEFAULT_TOTP_ALGORITHM,
  DEFAULT_TOTP_DIGITS,
  DEFAULT_TOTP_PERIOD,
  generateRecoveryCodes,
  generateTotpSecret,
  isValidRecoveryCode,
  normalizeRecoveryInput,
  totpOtpauthUri,
  totpVerify,
  type Factor,
  type MfaProof,
  type MfaVerifyResult,
  type RecoveryEnrollmentResult,
  type RecoveryFactor,
  type TotpEnrollmentResult,
  type TotpFactor,
  type UserMfaPolicy,
  type WebAuthnEnrollmentResult,
  type WebAuthnFactor,
  type WebAuthnProof,
} from "./mfa.js";
import type {
  ConfirmWebAuthnFactorInput,
  EnrollWebAuthnFactorInput,
  IdentityStore,
  SetMfaPolicyInput,
} from "./store.js";
import { webauthnVerifyAssertion } from "./webauthn.js";
import {
  ARGON2ID_FLOOR,
  type CreateCredentialInput,
  type CreateSessionInput,
  type CreateSessionResult,
  type CreateUserInput,
  type CredId,
  type Credential,
  type FindCredentialInput,
  type ListOptions,
  type Page,
  type RotateCredentialInput,
  type SesId,
  type Session,
  type Status,
  type UpdateUserInput,
  type User,
  type UsrId,
  type VerifiedCredentialResult,
  type VerifyPasswordInput,
} from "./types.js";

// ─── Row shapes ───

interface UsrRow {
  id: string;
  status: Status;
  display_name: string | null;
  created_at: Date;
  updated_at: Date;
}

interface CredRow {
  id: string;
  usr_id: string;
  type: "password" | "passkey" | "oidc";
  identifier: string;
  status: Status;
  replaces: string | null;
  password_hash: string | null;
  passkey_public_key: Buffer | null;
  passkey_sign_count: string | number | null;
  passkey_rp_id: string | null;
  oidc_issuer: string | null;
  oidc_subject: string | null;
  created_at: Date;
  updated_at: Date;
}

interface SesRow {
  id: string;
  usr_id: string;
  cred_id: string;
  created_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  token_hash: Buffer | null;
  mfa_verified_at: Date | null;
}

interface MfaRow {
  id: string;
  usr_id: string;
  type: "totp" | "webauthn" | "recovery";
  status: "pending" | "active" | "suspended" | "revoked";
  replaces: string | null;
  identifier: string | null;
  totp_secret: Buffer | null;
  totp_algorithm: "sha1" | "sha256" | "sha512" | null;
  totp_digits: number | null;
  totp_period: number | null;
  webauthn_public_key: Buffer | null;
  webauthn_sign_count: string | number | null;
  webauthn_rp_id: string | null;
  webauthn_aaguid: string | null;
  webauthn_transports: string[] | null;
  recovery_hashes: string[] | null;
  recovery_consumed: boolean[] | null;
  pending_expires_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

interface UsrMfaPolicyRow {
  usr_id: string;
  required: boolean;
  grace_until: Date | null;
  updated_at: Date;
}

// ─── Mappers ───

function rowToUser(r: UsrRow): User {
  return {
    id: encode("usr", r.id) as UsrId,
    status: r.status,
    displayName: r.display_name,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

function rowToCredential(r: CredRow): Credential {
  const base = {
    id: encode("cred", r.id) as CredId,
    usrId: encode("usr", r.usr_id) as UsrId,
    identifier: r.identifier,
    status: r.status,
    replaces: r.replaces ? (encode("cred", r.replaces) as CredId) : null,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
  if (r.type === "password") {
    return { ...base, type: "password" };
  }
  if (r.type === "passkey") {
    return {
      ...base,
      type: "passkey",
      passkeySignCount: Number(r.passkey_sign_count ?? 0),
      passkeyRpId: r.passkey_rp_id ?? "",
    };
  }
  return {
    ...base,
    type: "oidc",
    oidcIssuer: r.oidc_issuer ?? "",
    oidcSubject: r.oidc_subject ?? "",
  };
}

function rowToSession(r: SesRow): Session {
  return {
    id: encode("ses", r.id) as SesId,
    usrId: encode("usr", r.usr_id) as UsrId,
    credId: encode("cred", r.cred_id) as CredId,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
    revokedAt: r.revoked_at,
  };
}

function rowToFactor(r: MfaRow): Factor {
  const id = encode("mfa", r.id) as `mfa_${string}`;
  const usrId = encode("usr", r.usr_id) as UsrId;
  const replaces = r.replaces ? (encode("mfa", r.replaces) as `mfa_${string}`) : null;
  if (r.type === "totp") {
    const f: TotpFactor = {
      type: "totp",
      id,
      usrId,
      identifier: r.identifier ?? "",
      status: r.status,
      replaces,
      createdAt: r.created_at,
      updatedAt: r.updated_at,
    };
    return f;
  }
  if (r.type === "webauthn") {
    const f: WebAuthnFactor = {
      type: "webauthn",
      id,
      usrId,
      identifier: r.identifier ?? "",
      status: r.status,
      replaces,
      rpId: r.webauthn_rp_id ?? "",
      signCount: Number(r.webauthn_sign_count ?? 0),
      createdAt: r.created_at,
      updatedAt: r.updated_at,
    };
    return f;
  }
  const consumed = r.recovery_consumed ?? [];
  const remaining = consumed.filter((c) => !c).length;
  const f: RecoveryFactor = {
    type: "recovery",
    id,
    usrId,
    status: r.status,
    replaces,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    remaining,
  };
  return f;
}

function rowToPolicy(r: UsrMfaPolicyRow): UserMfaPolicy {
  return {
    usrId: encode("usr", r.usr_id) as UsrId,
    required: r.required,
    graceUntil: r.grace_until,
    updatedAt: r.updated_at,
  };
}

const CRED_COLS =
  "id, usr_id, type, identifier, status, replaces, password_hash, " +
  "passkey_public_key, passkey_sign_count, passkey_rp_id, " +
  "oidc_issuer, oidc_subject, created_at, updated_at";

const SES_COLS =
  "id, usr_id, cred_id, created_at, expires_at, revoked_at, token_hash, mfa_verified_at";

const MFA_COLS =
  "id, usr_id, type, status, replaces, identifier, " +
  "totp_secret, totp_algorithm, totp_digits, totp_period, " +
  "webauthn_public_key, webauthn_sign_count, webauthn_rp_id, " +
  "webauthn_aaguid, webauthn_transports, " +
  "recovery_hashes, recovery_consumed, pending_expires_at, " +
  "created_at, updated_at";

function wireToUuid(wireId: string): string {
  return decode(wireId).uuid;
}

function hashTokenBytes(token: string): Buffer {
  return createHash("sha256").update(token).digest();
}

function timingSafeBufferEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

function generateToken(): string {
  return randomBytes(32).toString("base64url");
}

// ─── Errors helpers ───

function isUniqueViolation(err: unknown): boolean {
  return (
    typeof err === "object"
    && err !== null
    && (err as { code?: string }).code === "23505"
  );
}

// ─── Store ───

export interface PostgresIdentityStoreOptions {
  /** Override the clock for deterministic tests. */
  clock?: () => Date;
}

export class PostgresIdentityStore implements IdentityStore {
  /** Pending TOTP/WebAuthn factor TTL per ADR 0008. */
  static readonly PENDING_FACTOR_TTL_SECONDS = 600;

  private readonly clock: () => Date;

  constructor(
    private readonly pool: Pool,
    options: PostgresIdentityStoreOptions = {},
  ) {
    this.clock = options.clock ?? (() => new Date());
  }

  private now(): Date {
    return this.clock();
  }

  private async tx<T>(fn: (c: PoolClient) => Promise<T>): Promise<T> {
    const c = await this.pool.connect();
    try {
      await c.query("BEGIN");
      const out = await fn(c);
      await c.query("COMMIT");
      return out;
    } catch (err) {
      await c.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      c.release();
    }
  }

  // ─── Users ───

  async createUser(input?: CreateUserInput): Promise<User> {
    const id = decode(generate("usr")).uuid;
    const { rows } = await this.pool.query<UsrRow>(
      `INSERT INTO usr (id, display_name) VALUES ($1, $2)
       RETURNING id, status, display_name, created_at, updated_at`,
      [id, input?.displayName ?? null],
    );
    return rowToUser(rows[0]!);
  }

  async getUser(usrId: UsrId): Promise<User> {
    const { rows } = await this.pool.query<UsrRow>(
      `SELECT id, status, display_name, created_at, updated_at FROM usr WHERE id = $1`,
      [wireToUuid(usrId)],
    );
    if (rows.length === 0) throw new NotFoundError(`User ${usrId} not found`);
    return rowToUser(rows[0]!);
  }

  async updateUser(input: UpdateUserInput): Promise<User> {
    return this.tx(async (c) => {
      const uuid = wireToUuid(input.usrId);
      const { rows: cur } = await c.query<UsrRow>(
        `SELECT id, status, display_name, created_at, updated_at
         FROM usr WHERE id = $1 FOR UPDATE`,
        [uuid],
      );
      if (cur.length === 0) throw new NotFoundError(`User ${input.usrId} not found`);
      const u = cur[0]!;
      if (u.status === "revoked") {
        throw new AlreadyTerminalError(`User ${input.usrId} is revoked; cannot update`);
      }
      const newDisplayName =
        "displayName" in input ? input.displayName ?? null : u.display_name;
      if (newDisplayName === u.display_name) {
        return rowToUser(u);
      }
      const { rows } = await c.query<UsrRow>(
        `UPDATE usr SET display_name = $1, updated_at = now()
         WHERE id = $2
         RETURNING id, status, display_name, created_at, updated_at`,
        [newDisplayName, uuid],
      );
      return rowToUser(rows[0]!);
    });
  }

  async suspendUser(usrId: UsrId): Promise<User> {
    return this.tx(async (c) => {
      const uuid = wireToUuid(usrId);
      const cur = await c.query<UsrRow>(
        `SELECT id, status, display_name, created_at, updated_at FROM usr WHERE id = $1 FOR UPDATE`,
        [uuid],
      );
      if (cur.rows.length === 0) {
        throw new NotFoundError(`User ${usrId} not found`);
      }
      const u = cur.rows[0]!;
      if (u.status === "revoked") {
        throw new AlreadyTerminalError(`User ${usrId} is revoked`);
      }
      if (u.status === "suspended") {
        return rowToUser(u);
      }
      const { rows } = await c.query<UsrRow>(
        `UPDATE usr SET status = 'suspended' WHERE id = $1
         RETURNING id, status, display_name, created_at, updated_at`,
        [uuid],
      );
      await c.query(
        `UPDATE ses SET revoked_at = $2
         WHERE usr_id = $1 AND revoked_at IS NULL`,
        [uuid, this.now()],
      );
      return rowToUser(rows[0]!);
    });
  }

  async reinstateUser(usrId: UsrId): Promise<User> {
    return this.tx(async (c) => {
      const uuid = wireToUuid(usrId);
      const cur = await c.query<UsrRow>(
        `SELECT id, status, display_name, created_at, updated_at FROM usr WHERE id = $1 FOR UPDATE`,
        [uuid],
      );
      if (cur.rows.length === 0) {
        throw new NotFoundError(`User ${usrId} not found`);
      }
      const u = cur.rows[0]!;
      if (u.status !== "suspended") {
        throw new PreconditionError(
          `User ${usrId} is ${u.status}; only suspended users can be reinstated`,
          "invalid_transition",
        );
      }
      const { rows } = await c.query<UsrRow>(
        `UPDATE usr SET status = 'active' WHERE id = $1
         RETURNING id, status, display_name, created_at, updated_at`,
        [uuid],
      );
      return rowToUser(rows[0]!);
    });
  }

  async revokeUser(usrId: UsrId): Promise<User> {
    return this.tx(async (c) => {
      const uuid = wireToUuid(usrId);
      const cur = await c.query<UsrRow>(
        `SELECT id, status, display_name, created_at, updated_at FROM usr WHERE id = $1 FOR UPDATE`,
        [uuid],
      );
      if (cur.rows.length === 0) {
        throw new NotFoundError(`User ${usrId} not found`);
      }
      const u = cur.rows[0]!;
      if (u.status === "revoked") {
        throw new AlreadyTerminalError(`User ${usrId} is already revoked`);
      }
      const now = this.now();
      // Cascade: revoke active credentials, terminate active sessions.
      await c.query(
        `UPDATE cred SET status = 'revoked'
         WHERE usr_id = $1 AND status = 'active'`,
        [uuid],
      );
      await c.query(
        `UPDATE ses SET revoked_at = $2
         WHERE usr_id = $1 AND revoked_at IS NULL`,
        [uuid, now],
      );
      const { rows } = await c.query<UsrRow>(
        `UPDATE usr SET status = 'revoked' WHERE id = $1
         RETURNING id, status, display_name, created_at, updated_at`,
        [uuid],
      );
      return rowToUser(rows[0]!);
    });
  }

  // ─── Credentials ───

  async createCredential(input: CreateCredentialInput): Promise<Credential> {
    const userUuid = wireToUuid(input.usrId);
    const userRes = await this.pool.query<UsrRow>(
      `SELECT status FROM usr WHERE id = $1`,
      [userUuid],
    );
    if (userRes.rows.length === 0) {
      throw new NotFoundError(`User ${input.usrId} not found`);
    }
    if (userRes.rows[0]!.status !== "active") {
      throw new PreconditionError(
        `Cannot create credentials for ${userRes.rows[0]!.status} user`,
        "user_not_active",
      );
    }
    const id = decode(generate("cred")).uuid;
    try {
      let row: CredRow;
      if (input.type === "password") {
        const hash = await argon2.hash(input.password, {
          type: argon2.argon2id,
          memoryCost: ARGON2ID_FLOOR.memoryCost,
          timeCost: ARGON2ID_FLOOR.timeCost,
          parallelism: ARGON2ID_FLOOR.parallelism,
        });
        const { rows } = await this.pool.query<CredRow>(
          `INSERT INTO cred (id, usr_id, type, identifier, password_hash)
           VALUES ($1, $2, 'password', $3, $4)
           RETURNING ${CRED_COLS}`,
          [id, userUuid, input.identifier, hash],
        );
        row = rows[0]!;
      } else if (input.type === "passkey") {
        const { rows } = await this.pool.query<CredRow>(
          `INSERT INTO cred (id, usr_id, type, identifier,
                             passkey_public_key, passkey_sign_count, passkey_rp_id)
           VALUES ($1, $2, 'passkey', $3, $4, $5, $6)
           RETURNING ${CRED_COLS}`,
          [
            id,
            userUuid,
            input.identifier,
            Buffer.from(input.publicKey),
            input.signCount,
            input.rpId,
          ],
        );
        row = rows[0]!;
      } else {
        const { rows } = await this.pool.query<CredRow>(
          `INSERT INTO cred (id, usr_id, type, identifier,
                             oidc_issuer, oidc_subject)
           VALUES ($1, $2, 'oidc', $3, $4, $5)
           RETURNING ${CRED_COLS}`,
          [id, userUuid, input.identifier, input.oidcIssuer, input.oidcSubject],
        );
        row = rows[0]!;
      }
      return rowToCredential(row);
    } catch (err) {
      if (isUniqueViolation(err)) {
        throw new DuplicateCredentialError(
          `An active ${input.type} credential already exists for identifier ${input.identifier}`,
        );
      }
      throw err;
    }
  }

  async getCredential(credId: CredId): Promise<Credential> {
    const { rows } = await this.pool.query<CredRow>(
      `SELECT ${CRED_COLS} FROM cred WHERE id = $1`,
      [wireToUuid(credId)],
    );
    if (rows.length === 0) {
      throw new NotFoundError(`Credential ${credId} not found`);
    }
    return rowToCredential(rows[0]!);
  }

  async listCredentialsForUser(usrId: UsrId): Promise<Credential[]> {
    const { rows } = await this.pool.query<CredRow>(
      `SELECT ${CRED_COLS} FROM cred WHERE usr_id = $1 ORDER BY created_at`,
      [wireToUuid(usrId)],
    );
    return rows.map(rowToCredential);
  }

  async findCredentialByIdentifier(
    input: FindCredentialInput,
  ): Promise<Credential | null> {
    const { rows } = await this.pool.query<CredRow>(
      `SELECT ${CRED_COLS} FROM cred
       WHERE type = $1 AND identifier = $2 AND status = 'active'`,
      [input.type, input.identifier],
    );
    if (rows.length === 0) return null;
    return rowToCredential(rows[0]!);
  }

  async rotateCredential(input: RotateCredentialInput): Promise<Credential> {
    return this.tx(async (c) => {
      const oldUuid = wireToUuid(input.credId);
      const cur = await c.query<CredRow>(
        `SELECT ${CRED_COLS} FROM cred WHERE id = $1 FOR UPDATE`,
        [oldUuid],
      );
      if (cur.rows.length === 0) {
        throw new NotFoundError(`Credential ${input.credId} not found`);
      }
      const old = cur.rows[0]!;
      if (old.status !== "active") {
        throw new CredentialNotActiveError(
          `Credential ${input.credId} is ${old.status}`,
        );
      }
      if (old.type !== input.type) {
        throw new CredentialTypeMismatchError(
          `Cannot rotate ${old.type} credential with ${input.type} payload`,
        );
      }
      const now = this.now();
      // Revoke old + cascade sessions.
      await c.query(`UPDATE cred SET status = 'revoked' WHERE id = $1`, [oldUuid]);
      await c.query(
        `UPDATE ses SET revoked_at = $2
         WHERE cred_id = $1 AND revoked_at IS NULL`,
        [oldUuid, now],
      );
      // Insert new with `replaces` chain pointer.
      const newId = decode(generate("cred")).uuid;
      let row: CredRow;
      if (input.type === "password") {
        const hash = await argon2.hash(input.newPassword, {
          type: argon2.argon2id,
          memoryCost: ARGON2ID_FLOOR.memoryCost,
          timeCost: ARGON2ID_FLOOR.timeCost,
          parallelism: ARGON2ID_FLOOR.parallelism,
        });
        const { rows } = await c.query<CredRow>(
          `INSERT INTO cred (id, usr_id, type, identifier, password_hash, replaces)
           VALUES ($1, $2, 'password', $3, $4, $5)
           RETURNING ${CRED_COLS}`,
          [newId, old.usr_id, old.identifier, hash, oldUuid],
        );
        row = rows[0]!;
      } else if (input.type === "passkey") {
        const { rows } = await c.query<CredRow>(
          `INSERT INTO cred (id, usr_id, type, identifier,
                             passkey_public_key, passkey_sign_count, passkey_rp_id, replaces)
           VALUES ($1, $2, 'passkey', $3, $4, $5, $6, $7)
           RETURNING ${CRED_COLS}`,
          [
            newId,
            old.usr_id,
            old.identifier,
            Buffer.from(input.publicKey),
            input.signCount,
            input.rpId,
            oldUuid,
          ],
        );
        row = rows[0]!;
      } else {
        const { rows } = await c.query<CredRow>(
          `INSERT INTO cred (id, usr_id, type, identifier,
                             oidc_issuer, oidc_subject, replaces)
           VALUES ($1, $2, 'oidc', $3, $4, $5, $6)
           RETURNING ${CRED_COLS}`,
          [
            newId,
            old.usr_id,
            old.identifier,
            input.oidcIssuer,
            input.oidcSubject,
            oldUuid,
          ],
        );
        row = rows[0]!;
      }
      return rowToCredential(row);
    });
  }

  async suspendCredential(credId: CredId): Promise<Credential> {
    return this.tx(async (c) => {
      const uuid = wireToUuid(credId);
      const cur = await c.query<CredRow>(
        `SELECT ${CRED_COLS} FROM cred WHERE id = $1 FOR UPDATE`,
        [uuid],
      );
      if (cur.rows.length === 0) {
        throw new NotFoundError(`Credential ${credId} not found`);
      }
      if (cur.rows[0]!.status !== "active") {
        throw new PreconditionError(
          `Credential ${credId} is ${cur.rows[0]!.status}; only active credentials can be suspended`,
          "cred_not_active",
        );
      }
      const { rows } = await c.query<CredRow>(
        `UPDATE cred SET status = 'suspended' WHERE id = $1
         RETURNING ${CRED_COLS}`,
        [uuid],
      );
      await c.query(
        `UPDATE ses SET revoked_at = $2
         WHERE cred_id = $1 AND revoked_at IS NULL`,
        [uuid, this.now()],
      );
      return rowToCredential(rows[0]!);
    });
  }

  async reinstateCredential(credId: CredId): Promise<Credential> {
    return this.tx(async (c) => {
      const uuid = wireToUuid(credId);
      const cur = await c.query<CredRow>(
        `SELECT ${CRED_COLS} FROM cred WHERE id = $1 FOR UPDATE`,
        [uuid],
      );
      if (cur.rows.length === 0) {
        throw new NotFoundError(`Credential ${credId} not found`);
      }
      const old = cur.rows[0]!;
      if (old.status !== "suspended") {
        throw new PreconditionError(
          `Credential ${credId} is ${old.status}; only suspended credentials can be reinstated`,
          "invalid_transition",
        );
      }
      try {
        const { rows } = await c.query<CredRow>(
          `UPDATE cred SET status = 'active' WHERE id = $1
           RETURNING ${CRED_COLS}`,
          [uuid],
        );
        return rowToCredential(rows[0]!);
      } catch (err) {
        if (isUniqueViolation(err)) {
          throw new DuplicateCredentialError(
            `Another active ${old.type} credential already exists for ${old.identifier}; cannot reinstate`,
          );
        }
        throw err;
      }
    });
  }

  async revokeCredential(credId: CredId): Promise<Credential> {
    return this.tx(async (c) => {
      const uuid = wireToUuid(credId);
      const cur = await c.query<CredRow>(
        `SELECT ${CRED_COLS} FROM cred WHERE id = $1 FOR UPDATE`,
        [uuid],
      );
      if (cur.rows.length === 0) {
        throw new NotFoundError(`Credential ${credId} not found`);
      }
      if (cur.rows[0]!.status === "revoked") {
        throw new AlreadyTerminalError(`Credential ${credId} is already revoked`);
      }
      const { rows } = await c.query<CredRow>(
        `UPDATE cred SET status = 'revoked' WHERE id = $1
         RETURNING ${CRED_COLS}`,
        [uuid],
      );
      await c.query(
        `UPDATE ses SET revoked_at = $2
         WHERE cred_id = $1 AND revoked_at IS NULL`,
        [uuid, this.now()],
      );
      return rowToCredential(rows[0]!);
    });
  }

  async verifyPassword(input: VerifyPasswordInput): Promise<VerifiedCredentialResult> {
    const { rows } = await this.pool.query<CredRow>(
      `SELECT ${CRED_COLS} FROM cred
       WHERE type = 'password' AND identifier = $1 AND status = 'active'`,
      [input.identifier],
    );
    if (rows.length === 0 || rows[0]!.password_hash === null) {
      throw new InvalidCredentialError(`Invalid credential`);
    }
    const cred = rows[0]!;
    const ok = await argon2.verify(cred.password_hash!, input.password);
    if (!ok) {
      throw new InvalidCredentialError(`Invalid credential`);
    }
    // ADR 0008: surface usr_mfa_policy state. Apps MUST gate
    // createSession on mfaRequired by calling verifyMfa first when true.
    const policyRes = await this.pool.query<{ required: boolean; grace_until: Date | null }>(
      `SELECT required, grace_until FROM usr_mfa_policy WHERE usr_id = $1`,
      [cred.usr_id],
    );
    let mfaRequired = false;
    if (policyRes.rows.length > 0 && policyRes.rows[0]!.required) {
      const grace = policyRes.rows[0]!.grace_until;
      if (grace === null || grace <= this.now()) {
        mfaRequired = true;
      }
    }
    return {
      usrId: encode("usr", cred.usr_id) as UsrId,
      credId: encode("cred", cred.id) as CredId,
      mfaRequired,
    };
  }

  // ─── Sessions ───

  async createSession(input: CreateSessionInput): Promise<CreateSessionResult> {
    const userUuid = wireToUuid(input.usrId);
    const credUuid = wireToUuid(input.credId);
    if (input.ttlSeconds < 60) {
      throw new PreconditionError(`ttlSeconds must be >= 60`, "ttl_too_short");
    }
    return this.tx(async (c) => {
      const userRes = await c.query<UsrRow>(
        `SELECT status FROM usr WHERE id = $1`,
        [userUuid],
      );
      if (userRes.rows.length === 0) {
        throw new NotFoundError(`User ${input.usrId} not found`);
      }
      if (userRes.rows[0]!.status !== "active") {
        throw new PreconditionError(
          `Cannot create session for ${userRes.rows[0]!.status} user`,
          "user_not_active",
        );
      }
      const credRes = await c.query<CredRow>(
        `SELECT status, usr_id FROM cred WHERE id = $1`,
        [credUuid],
      );
      if (credRes.rows.length === 0) {
        throw new NotFoundError(`Credential ${input.credId} not found`);
      }
      const cred = credRes.rows[0]!;
      if (cred.status !== "active") {
        throw new CredentialNotActiveError(
          `Credential ${input.credId} is ${cred.status}`,
        );
      }
      if (cred.usr_id !== userUuid) {
        throw new PreconditionError(
          `Credential ${input.credId} does not belong to ${input.usrId}`,
          "cred_user_mismatch",
        );
      }
      const now = this.now();
      const expiresAt = new Date(now.getTime() + input.ttlSeconds * 1000);
      const id = decode(generate("ses")).uuid;
      const token = generateToken();
      const tokenHash = hashTokenBytes(token);
      const { rows } = await c.query<SesRow>(
        `INSERT INTO ses (id, usr_id, cred_id, created_at, expires_at, token_hash)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING ${SES_COLS}`,
        [id, userUuid, credUuid, now, expiresAt, tokenHash],
      );
      return { session: rowToSession(rows[0]!), token };
    });
  }

  async getSession(sesId: SesId): Promise<Session> {
    const { rows } = await this.pool.query<SesRow>(
      `SELECT ${SES_COLS} FROM ses WHERE id = $1`,
      [wireToUuid(sesId)],
    );
    if (rows.length === 0) {
      throw new NotFoundError(`Session ${sesId} not found`);
    }
    return rowToSession(rows[0]!);
  }

  async listSessionsForUser(
    usrId: UsrId,
    options: ListOptions = {},
  ): Promise<Page<Session>> {
    const limit = Math.min(options.limit ?? 50, 200);
    const cursor = options.cursor;
    const params: unknown[] = [wireToUuid(usrId)];
    let where = "usr_id = $1";
    if (cursor) {
      params.push(wireToUuid(cursor));
      where += ` AND id > $${params.length}`;
    }
    params.push(limit + 1);
    const limitParam = params.length;
    const { rows } = await this.pool.query<SesRow>(
      `SELECT ${SES_COLS} FROM ses WHERE ${where}
       ORDER BY id LIMIT $${limitParam}`,
      params,
    );
    const data = rows.slice(0, limit).map(rowToSession);
    const nextCursor =
      rows.length > limit ? (data[data.length - 1]?.id ?? null) : null;
    return { data, nextCursor };
  }

  async verifySessionToken(token: string): Promise<Session> {
    const tokenHash = hashTokenBytes(token);
    const { rows } = await this.pool.query<SesRow>(
      `SELECT ${SES_COLS} FROM ses WHERE token_hash = $1`,
      [tokenHash],
    );
    if (rows.length === 0) {
      throw new InvalidTokenError(`Invalid token`);
    }
    const r = rows[0]!;
    if (r.token_hash === null || !timingSafeBufferEqual(tokenHash, r.token_hash)) {
      throw new InvalidTokenError(`Invalid token`);
    }
    if (r.revoked_at !== null) {
      throw new SessionExpiredError(`Session is revoked`);
    }
    if (this.now().getTime() > r.expires_at.getTime()) {
      throw new SessionExpiredError(`Session has expired`);
    }
    return rowToSession(r);
  }

  async refreshSession(sesId: SesId): Promise<CreateSessionResult> {
    return this.tx(async (c) => {
      const uuid = wireToUuid(sesId);
      const cur = await c.query<SesRow>(
        `SELECT ${SES_COLS} FROM ses WHERE id = $1 FOR UPDATE`,
        [uuid],
      );
      if (cur.rows.length === 0) {
        throw new NotFoundError(`Session ${sesId} not found`);
      }
      const old = cur.rows[0]!;
      if (old.revoked_at !== null) {
        throw new SessionExpiredError(`Session is already revoked`);
      }
      const now = this.now();
      if (now.getTime() > old.expires_at.getTime()) {
        throw new SessionExpiredError(`Session has expired`);
      }
      // Revoke old.
      await c.query(`UPDATE ses SET revoked_at = $2 WHERE id = $1`, [uuid, now]);
      const ttlMs = old.expires_at.getTime() - old.created_at.getTime();
      const newId = decode(generate("ses")).uuid;
      const token = generateToken();
      const tokenHash = hashTokenBytes(token);
      const { rows } = await c.query<SesRow>(
        `INSERT INTO ses (id, usr_id, cred_id, created_at, expires_at, token_hash)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING ${SES_COLS}`,
        [
          newId,
          old.usr_id,
          old.cred_id,
          now,
          new Date(now.getTime() + ttlMs),
          tokenHash,
        ],
      );
      return { session: rowToSession(rows[0]!), token };
    });
  }

  async revokeSession(sesId: SesId): Promise<Session> {
    const uuid = wireToUuid(sesId);
    const { rows } = await this.pool.query<SesRow>(
      `UPDATE ses SET revoked_at = COALESCE(revoked_at, $2)
       WHERE id = $1
       RETURNING ${SES_COLS}`,
      [uuid, this.now()],
    );
    if (rows.length === 0) {
      throw new NotFoundError(`Session ${sesId} not found`);
    }
    return rowToSession(rows[0]!);
  }

  // ─── MFA ───

  private async requireUserActive(c: PoolClient | Pool, usrId: UsrId): Promise<void> {
    const userUuid = wireToUuid(usrId);
    const { rows } = await c.query<UsrRow>(
      `SELECT status FROM usr WHERE id = $1`,
      [userUuid],
    );
    if (rows.length === 0) throw new NotFoundError(`User ${usrId} not found`);
    if (rows[0]!.status !== "active") {
      throw new PreconditionError(
        `User ${usrId} is ${rows[0]!.status}; cannot enroll MFA`,
        "user_not_active",
      );
    }
  }

  async enrollTotpFactor(
    usrId: UsrId,
    identifier: string,
  ): Promise<TotpEnrollmentResult> {
    await this.requireUserActive(this.pool, usrId);
    const userUuid = wireToUuid(usrId);
    // The partial-unique index `mfa_unique_active_singleton` only fires
    // on status = 'active'; new TOTP factors are inserted as 'pending',
    // so duplicate-active checks have to happen explicitly.
    const existing = await this.pool.query(
      `SELECT 1 FROM mfa
       WHERE usr_id = $1 AND type = 'totp' AND status = 'active'`,
      [userUuid],
    );
    if (existing.rows.length > 0) {
      throw new PreconditionError(
        `User ${usrId} already has an active totp factor; revoke before re-enrolling`,
        "active_singleton_exists",
      );
    }
    const now = this.now();
    const secret = generateTotpSecret();
    const id = decode(generate("mfa")).uuid;
    const expiresAt = new Date(
      now.getTime() + PostgresIdentityStore.PENDING_FACTOR_TTL_SECONDS * 1000,
    );
    try {
      const { rows } = await this.pool.query<MfaRow>(
        `INSERT INTO mfa (id, usr_id, type, status, identifier,
                          totp_secret, totp_algorithm, totp_digits, totp_period,
                          pending_expires_at, created_at, updated_at)
         VALUES ($1, $2, 'totp', 'pending', $3,
                 $4, $5, $6, $7, $8, $9, $9)
         RETURNING ${MFA_COLS}`,
        [
          id,
          userUuid,
          identifier,
          Buffer.from(secret),
          DEFAULT_TOTP_ALGORITHM,
          DEFAULT_TOTP_DIGITS,
          DEFAULT_TOTP_PERIOD,
          expiresAt,
          now,
        ],
      );
      const factor = rowToFactor(rows[0]!) as TotpFactor;
      return {
        factor,
        secretB32: base32Encode(secret).replace(/=+$/, ""),
        otpauthUri: totpOtpauthUri({
          secret,
          label: identifier,
          issuer: "Flametrench",
        }),
      };
    } catch (err) {
      if (isUniqueViolation(err)) {
        throw new PreconditionError(
          `User ${usrId} already has an active totp factor; revoke before re-enrolling`,
          "active_singleton_exists",
        );
      }
      throw err;
    }
  }

  async enrollWebAuthnFactor(
    input: EnrollWebAuthnFactorInput,
  ): Promise<WebAuthnEnrollmentResult> {
    await this.requireUserActive(this.pool, input.usrId);
    const userUuid = wireToUuid(input.usrId);
    const now = this.now();
    const id = decode(generate("mfa")).uuid;
    const expiresAt = new Date(
      now.getTime() + PostgresIdentityStore.PENDING_FACTOR_TTL_SECONDS * 1000,
    );
    try {
      const { rows } = await this.pool.query<MfaRow>(
        `INSERT INTO mfa (id, usr_id, type, status, identifier,
                          webauthn_public_key, webauthn_sign_count, webauthn_rp_id,
                          webauthn_aaguid, webauthn_transports,
                          pending_expires_at, created_at, updated_at)
         VALUES ($1, $2, 'webauthn', 'pending', $3,
                 $4, $5, $6, $7, $8, $9, $10, $10)
         RETURNING ${MFA_COLS}`,
        [
          id,
          userUuid,
          input.identifier,
          Buffer.from(input.publicKey),
          input.signCount,
          input.rpId,
          input.aaguid ?? null,
          input.transports ?? null,
          expiresAt,
          now,
        ],
      );
      return { factor: rowToFactor(rows[0]!) as WebAuthnFactor };
    } catch (err) {
      if (isUniqueViolation(err)) {
        throw new PreconditionError(
          `WebAuthn credential ${JSON.stringify(input.identifier)} is already enrolled`,
          "duplicate_webauthn_credential",
        );
      }
      throw err;
    }
  }

  async enrollRecoveryFactor(usrId: UsrId): Promise<RecoveryEnrollmentResult> {
    await this.requireUserActive(this.pool, usrId);
    const userUuid = wireToUuid(usrId);
    const now = this.now();
    const codes = generateRecoveryCodes();
    const hashes = await Promise.all(codes.map((code) => hashPassword(code)));
    const consumed = codes.map(() => false);
    const id = decode(generate("mfa")).uuid;
    try {
      const { rows } = await this.pool.query<MfaRow>(
        `INSERT INTO mfa (id, usr_id, type, status,
                          recovery_hashes, recovery_consumed,
                          created_at, updated_at)
         VALUES ($1, $2, 'recovery', 'active', $3, $4, $5, $5)
         RETURNING ${MFA_COLS}`,
        [id, userUuid, hashes, consumed, now],
      );
      return { factor: rowToFactor(rows[0]!) as RecoveryFactor, codes };
    } catch (err) {
      if (isUniqueViolation(err)) {
        throw new PreconditionError(
          `User ${usrId} already has an active recovery factor; revoke before re-enrolling`,
          "active_singleton_exists",
        );
      }
      throw err;
    }
  }

  async getMfaFactor(mfaId: string): Promise<Factor> {
    const { rows } = await this.pool.query<MfaRow>(
      `SELECT ${MFA_COLS} FROM mfa WHERE id = $1`,
      [wireToUuid(mfaId)],
    );
    if (rows.length === 0) {
      throw new NotFoundError(`MFA factor ${mfaId} not found`);
    }
    return rowToFactor(rows[0]!);
  }

  async listMfaFactors(usrId: UsrId): Promise<Factor[]> {
    const { rows } = await this.pool.query<MfaRow>(
      `SELECT ${MFA_COLS} FROM mfa WHERE usr_id = $1 ORDER BY created_at`,
      [wireToUuid(usrId)],
    );
    return rows.map(rowToFactor);
  }

  async confirmTotpFactor(mfaId: string, code: string): Promise<TotpFactor> {
    return this.tx(async (c) => {
      const uuid = wireToUuid(mfaId);
      const cur = await c.query<MfaRow>(
        `SELECT ${MFA_COLS} FROM mfa WHERE id = $1 FOR UPDATE`,
        [uuid],
      );
      if (cur.rows.length === 0) {
        throw new NotFoundError(`MFA factor ${mfaId} not found`);
      }
      const r = cur.rows[0]!;
      if (r.type !== "totp") {
        throw new CredentialTypeMismatchError(
          `Factor ${mfaId} is ${r.type}, not totp`,
        );
      }
      if (r.status !== "pending") {
        throw new PreconditionError(
          `Factor ${mfaId} is ${r.status}; only pending factors confirm`,
          "factor_not_pending",
        );
      }
      this.checkPendingNotExpired(r);
      const ok = totpVerify(r.totp_secret!, code, {
        timestamp: Math.floor(this.now().getTime() / 1000),
      });
      if (!ok) {
        throw new InvalidCredentialError("TOTP code did not verify");
      }
      const { rows } = await c.query<MfaRow>(
        `UPDATE mfa SET status = 'active', pending_expires_at = NULL WHERE id = $1
         RETURNING ${MFA_COLS}`,
        [uuid],
      );
      return rowToFactor(rows[0]!) as TotpFactor;
    });
  }

  async confirmWebAuthnFactor(
    input: ConfirmWebAuthnFactorInput,
  ): Promise<WebAuthnFactor> {
    return this.tx(async (c) => {
      const uuid = wireToUuid(input.mfaId);
      const cur = await c.query<MfaRow>(
        `SELECT ${MFA_COLS} FROM mfa WHERE id = $1 FOR UPDATE`,
        [uuid],
      );
      if (cur.rows.length === 0) {
        throw new NotFoundError(`MFA factor ${input.mfaId} not found`);
      }
      const r = cur.rows[0]!;
      if (r.type !== "webauthn") {
        throw new CredentialTypeMismatchError(
          `Factor ${input.mfaId} is ${r.type}, not webauthn`,
        );
      }
      if (r.status !== "pending") {
        throw new PreconditionError(
          `Factor ${input.mfaId} is ${r.status}; only pending factors confirm`,
          "factor_not_pending",
        );
      }
      this.checkPendingNotExpired(r);
      const result = webauthnVerifyAssertion({
        cosePublicKey: r.webauthn_public_key!,
        storedSignCount: Number(r.webauthn_sign_count ?? 0),
        storedRpId: r.webauthn_rp_id!,
        expectedChallenge: input.expectedChallenge,
        expectedOrigin: input.expectedOrigin,
        authenticatorData: input.authenticatorData,
        clientDataJson: input.clientDataJson,
        signature: input.signature,
      });
      const { rows } = await c.query<MfaRow>(
        `UPDATE mfa SET status = 'active', webauthn_sign_count = $2,
                        pending_expires_at = NULL
         WHERE id = $1
         RETURNING ${MFA_COLS}`,
        [uuid, result.newSignCount],
      );
      return rowToFactor(rows[0]!) as WebAuthnFactor;
    });
  }

  async revokeMfaFactor(mfaId: string): Promise<Factor> {
    return this.tx(async (c) => {
      const uuid = wireToUuid(mfaId);
      const cur = await c.query<MfaRow>(
        `SELECT ${MFA_COLS} FROM mfa WHERE id = $1 FOR UPDATE`,
        [uuid],
      );
      if (cur.rows.length === 0) {
        throw new NotFoundError(`MFA factor ${mfaId} not found`);
      }
      if (cur.rows[0]!.status === "revoked") {
        return rowToFactor(cur.rows[0]!);
      }
      const { rows } = await c.query<MfaRow>(
        `UPDATE mfa SET status = 'revoked', pending_expires_at = NULL WHERE id = $1
         RETURNING ${MFA_COLS}`,
        [uuid],
      );
      return rowToFactor(rows[0]!);
    });
  }

  async verifyMfa(usrId: UsrId, proof: MfaProof): Promise<MfaVerifyResult> {
    if (proof.type === "totp") return this.verifyTotpProof(usrId, proof.code);
    if (proof.type === "webauthn") return this.verifyWebAuthnProof(usrId, proof);
    return this.verifyRecoveryProof(usrId, proof.code);
  }

  private async verifyTotpProof(
    usrId: UsrId,
    code: string,
  ): Promise<MfaVerifyResult> {
    const { rows } = await this.pool.query<MfaRow>(
      `SELECT ${MFA_COLS} FROM mfa
       WHERE usr_id = $1 AND type = 'totp' AND status = 'active'`,
      [wireToUuid(usrId)],
    );
    if (rows.length === 0) {
      throw new InvalidCredentialError("No active TOTP factor for user");
    }
    const r = rows[0]!;
    const ok = totpVerify(r.totp_secret!, code, {
      timestamp: Math.floor(this.now().getTime() / 1000),
    });
    if (!ok) throw new InvalidCredentialError("TOTP code did not verify");
    return {
      mfaId: encode("mfa", r.id) as `mfa_${string}`,
      type: "totp",
      mfaVerifiedAt: this.now(),
      newSignCount: null,
    };
  }

  private async verifyWebAuthnProof(
    usrId: UsrId,
    proof: WebAuthnProof,
  ): Promise<MfaVerifyResult> {
    return this.tx(async (c) => {
      const userUuid = wireToUuid(usrId);
      const cur = await c.query<MfaRow>(
        `SELECT ${MFA_COLS} FROM mfa
         WHERE identifier = $1 AND type = 'webauthn' AND status = 'active'
         FOR UPDATE`,
        [proof.credentialId],
      );
      if (cur.rows.length === 0) {
        throw new InvalidCredentialError("No WebAuthn factor for credential id");
      }
      const r = cur.rows[0]!;
      if (r.usr_id !== userUuid) {
        // Generic — don't leak which user owns the credential.
        throw new InvalidCredentialError("WebAuthn factor does not belong to user");
      }
      const result = webauthnVerifyAssertion({
        cosePublicKey: r.webauthn_public_key!,
        storedSignCount: Number(r.webauthn_sign_count ?? 0),
        storedRpId: r.webauthn_rp_id!,
        expectedChallenge: proof.expectedChallenge,
        expectedOrigin: proof.expectedOrigin,
        authenticatorData: proof.authenticatorData,
        clientDataJson: proof.clientDataJson,
        signature: proof.signature,
      });
      await c.query(
        `UPDATE mfa SET webauthn_sign_count = $2 WHERE id = $1`,
        [r.id, result.newSignCount],
      );
      return {
        mfaId: encode("mfa", r.id) as `mfa_${string}`,
        type: "webauthn",
        mfaVerifiedAt: this.now(),
        newSignCount: result.newSignCount,
      };
    });
  }

  private async verifyRecoveryProof(
    usrId: UsrId,
    code: string,
  ): Promise<MfaVerifyResult> {
    const normalized = normalizeRecoveryInput(code);
    if (!isValidRecoveryCode(normalized)) {
      throw new InvalidCredentialError("Recovery code is malformed");
    }
    return this.tx(async (c) => {
      const cur = await c.query<MfaRow>(
        `SELECT ${MFA_COLS} FROM mfa
         WHERE usr_id = $1 AND type = 'recovery' AND status = 'active'
         FOR UPDATE`,
        [wireToUuid(usrId)],
      );
      if (cur.rows.length === 0) {
        throw new InvalidCredentialError("No active recovery factor for user");
      }
      const r = cur.rows[0]!;
      const hashes = r.recovery_hashes!;
      const consumed = [...r.recovery_consumed!];
      // Walk every active slot regardless of an early match — keeps work
      // constant relative to the active set so timing doesn't leak which
      // slot matched.
      let matchedSlot = -1;
      for (let i = 0; i < hashes.length; i++) {
        if (consumed[i]) continue;
        const ok = await verifyPasswordHash(hashes[i]!, normalized);
        if (ok && matchedSlot === -1) matchedSlot = i;
      }
      if (matchedSlot === -1) {
        throw new InvalidCredentialError("Recovery code did not verify");
      }
      consumed[matchedSlot] = true;
      await c.query(
        `UPDATE mfa SET recovery_consumed = $2 WHERE id = $1`,
        [r.id, consumed],
      );
      return {
        mfaId: encode("mfa", r.id) as `mfa_${string}`,
        type: "recovery",
        mfaVerifiedAt: this.now(),
        newSignCount: null,
      };
    });
  }

  async getMfaPolicy(usrId: UsrId): Promise<UserMfaPolicy | null> {
    const userUuid = wireToUuid(usrId);
    const userRes = await this.pool.query<UsrRow>(
      `SELECT id FROM usr WHERE id = $1`,
      [userUuid],
    );
    if (userRes.rows.length === 0) {
      throw new NotFoundError(`User ${usrId} not found`);
    }
    const { rows } = await this.pool.query<UsrMfaPolicyRow>(
      `SELECT usr_id, required, grace_until, updated_at
       FROM usr_mfa_policy WHERE usr_id = $1`,
      [userUuid],
    );
    if (rows.length === 0) return null;
    return rowToPolicy(rows[0]!);
  }

  async setMfaPolicy(input: SetMfaPolicyInput): Promise<UserMfaPolicy> {
    const userUuid = wireToUuid(input.usrId);
    const userRes = await this.pool.query<UsrRow>(
      `SELECT id FROM usr WHERE id = $1`,
      [userUuid],
    );
    if (userRes.rows.length === 0) {
      throw new NotFoundError(`User ${input.usrId} not found`);
    }
    const { rows } = await this.pool.query<UsrMfaPolicyRow>(
      `INSERT INTO usr_mfa_policy (usr_id, required, grace_until)
       VALUES ($1, $2, $3)
       ON CONFLICT (usr_id) DO UPDATE SET
         required = EXCLUDED.required,
         grace_until = EXCLUDED.grace_until
       RETURNING usr_id, required, grace_until, updated_at`,
      [userUuid, input.required, input.graceUntil ?? null],
    );
    return rowToPolicy(rows[0]!);
  }

  // ─── helpers ───

  private checkPendingNotExpired(r: MfaRow): void {
    if (r.status !== "pending") return;
    if (r.pending_expires_at !== null
      && this.now().getTime() > r.pending_expires_at.getTime()) {
      throw new PreconditionError(
        `Pending factor ${encode("mfa", r.id)} expired`,
        "pending_factor_expired",
      );
    }
  }
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
