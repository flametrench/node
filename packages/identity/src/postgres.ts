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
  InvalidPatTokenError,
  InvalidTokenError,
  NotFoundError,
  PatExpiredError,
  PatRevokedError,
  PreconditionError,
  SessionExpiredError,
} from "./errors.js";
import { hashPassword, verifyPasswordHash } from "./hashing.js";
import {
  PAT_DUMMY_PHC_HASH,
  PAT_MAX_LIFETIME_SECONDS,
  PAT_MAX_SECRET_LENGTH,
} from "./pat.js";
import type {
  CreatePatInput,
  CreatePatResult,
  ListPatsForUserOptions,
  PatId,
  PatStatus,
  PersonalAccessToken,
  VerifiedPat,
} from "./pat.js";
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
  type ListUsersOptions,
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

// ─── ADR 0013 savepoint helpers ───

/**
 * Read the immediate adapter method that called into `tx`/`nested`. Used
 * for savepoint names so logs (`pg_stat_activity`, `auto_explain`,
 * pgBadger) stay grep-able. Falls back to `"tx"` for closures or anonymous
 * frames. V8 stack format: parsing is best-effort; correctness of the
 * savepoint contract does NOT depend on the method-name lookup, only on
 * the random suffix.
 */
function callerName(): string {
  const stack = new Error().stack ?? "";
  const lines = stack.split("\n");
  // line 0: "Error", line 1: callerName, line 2: tx/nested, line 3: caller.
  const target = lines[3] ?? "";
  const m = target.match(/at\s+(?:async\s+)?(?:[\w$.]+\.)?([\w$]+)\s/);
  return m?.[1] ?? "tx";
}

/** Build a savepoint name matching ADR 0013: `ft_<method>_<random>`. */
function makeSavepointName(method: string): string {
  const sanitized = method.replace(/[^A-Za-z0-9]/g, "");
  const safe = sanitized.length > 0 ? sanitized : "tx";
  const rand = randomBytes(4).toString("hex");
  return `ft_${safe}_${rand}`;
}

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

const PAT_COLS =
  "id, usr_id, name, scope, secret_hash, expires_at, last_used_at, " +
  "revoked_at, created_at, updated_at";

interface PatRow {
  id: string;
  usr_id: string;
  name: string;
  scope: string[] | null;
  secret_hash: string;
  expires_at: Date | null;
  last_used_at: Date | null;
  revoked_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

function wireToUuid(wireId: string): string {
  return decode(wireId).uuid;
}

/** RFC 4648 §5 base64url, no padding. Matches the spec wire format. */
function base64UrlEncode(buf: Uint8Array): string {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
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
  /**
   * Coalescing window for `lastUsedAt` writes on `verifyPatToken` per
   * ADR 0016 §"Operational notes". Within this window, repeat verifies
   * of the same PAT do NOT issue an UPDATE. 0 disables coalescing.
   * Default 60 seconds.
   */
  patLastUsedCoalesceSeconds?: number;
}

/**
 * Connection types accepted by the Postgres adapter.
 *
 * - **`Pool`** — adapter owns transactions; each `tx()` call acquires a
 *   client, runs `BEGIN`/`COMMIT`, and releases. Single-statement queries
 *   run directly on the pool. This is the standalone case.
 * - **`PoolClient`** — caller owns the transaction (per ADR 0013). The
 *   adapter assumes the caller has already issued `BEGIN` (or will) and
 *   uses `SAVEPOINT`/`RELEASE` for its internal atomicity boundaries
 *   instead of opening its own transaction. Adopters wrapping multiple
 *   SDK calls in one outer transaction MUST construct every participating
 *   store with the same `PoolClient`.
 */
export type PostgresIdentityClient = Pool | PoolClient;

export class PostgresIdentityStore implements IdentityStore {
  /** Pending TOTP/WebAuthn factor TTL per ADR 0008. */
  static readonly PENDING_FACTOR_TTL_SECONDS = 600;

  private readonly clock: () => Date;
  private readonly patLastUsedCoalesceSeconds: number;

  constructor(
    private readonly pool: PostgresIdentityClient,
    options: PostgresIdentityStoreOptions = {},
  ) {
    this.clock = options.clock ?? (() => new Date());
    this.patLastUsedCoalesceSeconds = Math.max(
      0,
      options.patLastUsedCoalesceSeconds ?? 60,
    );
  }

  private now(): Date {
    return this.clock();
  }

  /**
   * True when the adapter was constructed with a caller-owned PoolClient
   * (vs a Pool). Detects via `release` — present on PoolClient (and only
   * called by callers when they're done with the checked-out client),
   * absent on Pool. Both types have `connect` and `query`, so those are
   * not distinguishing.
   */
  private get clientIsCallerOwned(): boolean {
    return typeof (this.pool as { release?: unknown }).release === "function";
  }

  /**
   * Run $fn atomically. Standalone (Pool): acquires a client, BEGIN/COMMIT,
   * release. Nested (PoolClient): SAVEPOINT/RELEASE on the existing client
   * per ADR 0013 — adapter cooperates with the caller's outer transaction.
   *
   * Savepoint name follows `ft_<method>_<random>`: method prefix preserves
   * grep-ability in pg_stat_activity; random suffix turns pairing bugs into
   * loud `savepoint does not exist` errors instead of silent half-commits.
   */
  private async tx<T>(fn: (c: PoolClient) => Promise<T>): Promise<T> {
    if (this.clientIsCallerOwned) {
      const c = this.pool as PoolClient;
      const sp = makeSavepointName(callerName());
      await c.query(`SAVEPOINT ${sp}`);
      try {
        const out = await fn(c);
        await c.query(`RELEASE SAVEPOINT ${sp}`);
        return out;
      } catch (err) {
        await c.query(`ROLLBACK TO SAVEPOINT ${sp}`).catch(() => {});
        await c.query(`RELEASE SAVEPOINT ${sp}`).catch(() => {});
        throw err;
      }
    }
    const c = await (this.pool as Pool).connect();
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

  /**
   * Shield $fn with a savepoint when the adapter is using a caller-owned
   * PoolClient (i.e. inside an adopter's outer transaction); pass through
   * directly when standalone (Pool). Used by single-statement methods that
   * don't need their own BEGIN/COMMIT but must not contaminate an outer
   * transaction on a constraint violation. Postgres aborts the entire
   * transaction on any statement-level error (SQLSTATE 25P02 for subsequent
   * statements) until the next ROLLBACK or ROLLBACK TO SAVEPOINT.
   */
  private async nested<T>(fn: () => Promise<T>): Promise<T> {
    if (!this.clientIsCallerOwned) return fn();
    const c = this.pool as PoolClient;
    const sp = makeSavepointName(callerName());
    await c.query(`SAVEPOINT ${sp}`);
    try {
      const out = await fn();
      await c.query(`RELEASE SAVEPOINT ${sp}`);
      return out;
    } catch (err) {
      await c.query(`ROLLBACK TO SAVEPOINT ${sp}`).catch(() => {});
      await c.query(`RELEASE SAVEPOINT ${sp}`).catch(() => {});
      throw err;
    }
  }

  // ─── Users ───

  async createUser(input?: CreateUserInput): Promise<User> {
    return this.nested(async () => {
      const id = decode(generate("usr")).uuid;
      const { rows } = await this.pool.query<UsrRow>(
        `INSERT INTO usr (id, display_name) VALUES ($1, $2)
         RETURNING id, status, display_name, created_at, updated_at`,
        [id, input?.displayName ?? null],
      );
      return rowToUser(rows[0]!);
    });
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

  async listUsers(options?: ListUsersOptions): Promise<Page<User>> {
    const limit = Math.max(1, Math.min(options?.limit ?? 50, 200));
    const params: unknown[] = [];
    let sql =
      `SELECT id, status, display_name, created_at, updated_at FROM usr WHERE 1=1`;
    if (options?.cursor !== undefined) {
      params.push(wireToUuid(options.cursor as UsrId));
      sql += ` AND id > $${params.length}`;
    }
    if (options?.status !== undefined) {
      params.push(options.status);
      sql += ` AND status = $${params.length}`;
    }
    if (options?.query !== undefined) {
      params.push(
        "%" +
          options.query.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_") +
          "%",
      );
      sql += ` AND EXISTS (
        SELECT 1 FROM cred
        WHERE cred.usr_id = usr.id
          AND cred.status = 'active'
          AND cred.identifier ILIKE $${params.length}
      )`;
    }
    params.push(limit + 1);
    sql += ` ORDER BY id LIMIT $${params.length}`;
    const { rows } = await this.pool.query<UsrRow>(sql, params);
    const slice = rows.slice(0, limit);
    const data = slice.map(rowToUser);
    const nextCursor =
      rows.length > limit && data.length > 0 ? data[data.length - 1]!.id : null;
    return { data, nextCursor };
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
    return this.nested(async () => {
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
    });
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

  // ─── v0.3 personal access tokens (ADR 0016) ───

  async createPat(input: CreatePatInput): Promise<CreatePatResult> {
    return this.tx(async (c) => {
      const userUuid = wireToUuid(input.usrId);
      const userRes = await c.query<{ status: string }>(
        `SELECT status FROM usr WHERE id = $1 FOR UPDATE`,
        [userUuid],
      );
      if (userRes.rows.length === 0) {
        throw new NotFoundError(`User ${input.usrId} not found`);
      }
      if (userRes.rows[0]!.status === "revoked") {
        throw new AlreadyTerminalError(
          `User ${input.usrId} is revoked; cannot issue PATs`,
        );
      }
      if (input.name.length < 1 || input.name.length > 120) {
        throw new PreconditionError(
          `PAT name must be 1–120 characters (got ${input.name.length})`,
          "pat.name_invalid",
        );
      }
      const now = this.now();
      if (input.expiresAt != null && input.expiresAt <= now) {
        throw new PreconditionError(
          "PAT expires_at must be strictly in the future",
          "pat.expires_in_past",
        );
      }
      // security-audit-v0.3.md H1: 365-day cap from ADR 0016 §"Constraints".
      if (
        input.expiresAt != null &&
        input.expiresAt.getTime() - now.getTime() > PAT_MAX_LIFETIME_SECONDS * 1000
      ) {
        throw new PreconditionError(
          `PAT expires_at exceeds the spec cap of ${PAT_MAX_LIFETIME_SECONDS} seconds (365 days) from creation`,
          "pat.expires_too_far",
        );
      }
      const patWireId = generate("pat") as PatId;
      const patUuid = wireToUuid(patWireId);
      const idHexSegment = patWireId.slice(4);
      const secretBytes = randomBytes(32);
      const secretSegment = base64UrlEncode(secretBytes);
      const token = `pat_${idHexSegment}_${secretSegment}`;
      const secretHash = await hashPassword(secretSegment);

      const insertRes = await c.query<PatRow>(
        `INSERT INTO pat (id, usr_id, name, scope, secret_hash, expires_at,
                          last_used_at, revoked_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, $7, $7)
         RETURNING ${PAT_COLS}`,
        [
          patUuid,
          userUuid,
          input.name,
          input.scope,
          secretHash,
          input.expiresAt ?? null,
          now,
        ],
      );
      return {
        pat: this.rowToPat(insertRes.rows[0]!),
        token,
      };
    });
  }

  async getPat(patId: PatId): Promise<PersonalAccessToken> {
    const res = await this.pool.query<PatRow>(
      `SELECT ${PAT_COLS} FROM pat WHERE id = $1`,
      [wireToUuid(patId)],
    );
    if (res.rows.length === 0) {
      throw new NotFoundError(`PAT ${patId} not found`);
    }
    return this.rowToPat(res.rows[0]!);
  }

  async listPatsForUser(
    usrId: UsrId,
    options: ListPatsForUserOptions = {},
  ): Promise<Page<PersonalAccessToken>> {
    const limit = Math.max(1, Math.min(options.limit ?? 50, 200));
    const params: unknown[] = [wireToUuid(usrId)];
    let sql = `SELECT ${PAT_COLS} FROM pat WHERE usr_id = $1`;
    if (options.cursor != null) {
      params.push(wireToUuid(options.cursor as PatId));
      sql += ` AND id > $${params.length}`;
    }
    if (options.status != null) {
      const now = this.now();
      switch (options.status) {
        case "revoked":
          sql += ` AND revoked_at IS NOT NULL`;
          break;
        case "expired":
          params.push(now);
          sql += ` AND revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at <= $${params.length}`;
          break;
        case "active":
          params.push(now);
          sql += ` AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $${params.length})`;
          break;
      }
    }
    params.push(limit + 1);
    sql += ` ORDER BY id ASC LIMIT $${params.length}`;
    const res = await this.pool.query<PatRow>(sql, params);
    const hasMore = res.rows.length > limit;
    const rows = hasMore ? res.rows.slice(0, limit) : res.rows;
    const data = rows.map((r) => this.rowToPat(r));
    const nextCursor = hasMore && data.length > 0 ? data[data.length - 1]!.id : null;
    return { data, nextCursor };
  }

  async revokePat(patId: PatId): Promise<PersonalAccessToken> {
    return this.tx(async (c) => {
      const lock = await c.query<PatRow>(
        `SELECT ${PAT_COLS} FROM pat WHERE id = $1 FOR UPDATE`,
        [wireToUuid(patId)],
      );
      if (lock.rows.length === 0) {
        throw new NotFoundError(`PAT ${patId} not found`);
      }
      if (lock.rows[0]!.revoked_at != null) {
        // Idempotent: already revoked.
        return this.rowToPat(lock.rows[0]!);
      }
      const now = this.now();
      const upd = await c.query<PatRow>(
        `UPDATE pat SET revoked_at = $1, updated_at = $1
         WHERE id = $2 RETURNING ${PAT_COLS}`,
        [now, wireToUuid(patId)],
      );
      return this.rowToPat(upd.rows[0]!);
    });
  }

  async verifyPatToken(token: string): Promise<VerifiedPat> {
    // Step 1–2: structural decode.
    if (!token.startsWith("pat_")) throw new InvalidPatTokenError();
    if (token.length < 4 + 32 + 1 + 1) throw new InvalidPatTokenError();
    const idHex = token.slice(4, 36);
    if (!/^[0-9a-f]{32}$/.test(idHex)) throw new InvalidPatTokenError();
    if (token[36] !== "_") throw new InvalidPatTokenError();
    const secretSegment = token.slice(37);
    // security-audit-v0.3.md H6: cap on secret-segment length —
    // see in-memory.ts for rationale. Reject before Argon2id dispatch.
    if (secretSegment.length === 0 || secretSegment.length > PAT_MAX_SECRET_LENGTH) {
      throw new InvalidPatTokenError();
    }
    const patId = `pat_${idHex}` as PatId;

    // Step 3: lookup. wireToUuid may throw if the structurally-valid
    // 32hex segment isn't a real UUID — for timing-oracle purposes
    // that's still "invalid token", so we conflate.
    let patUuid: string;
    try {
      patUuid = wireToUuid(patId);
    } catch {
      // security-audit-v0.3.md H2: timing-oracle defense for
      // structurally-valid-but-not-UUIDv7 ids.
      await verifyPasswordHash(PAT_DUMMY_PHC_HASH, secretSegment);
      throw new InvalidPatTokenError();
    }
    const res = await this.pool.query<PatRow>(
      `SELECT ${PAT_COLS} FROM pat WHERE id = $1`,
      [patUuid],
    );
    // Step 4: missing → conflated InvalidPatTokenError.
    // security-audit-v0.3.md H2: perform Argon2id verify against a
    // dummy hash before throwing so wall-clock time matches the
    // row-exists path. Defends against pat_id existence probing
    // via timing.
    if (res.rows.length === 0) {
      await verifyPasswordHash(PAT_DUMMY_PHC_HASH, secretSegment);
      throw new InvalidPatTokenError();
    }
    const r = res.rows[0]!;
    // Step 5: revoked terminal check.
    if (r.revoked_at != null) throw new PatRevokedError(patId);
    // Step 6: expiry.
    const now = this.now();
    if (r.expires_at != null && r.expires_at <= now) {
      throw new PatExpiredError(patId);
    }
    // Step 7: Argon2id verify; conflated error shape.
    if (!(await verifyPasswordHash(r.secret_hash, secretSegment))) {
      throw new InvalidPatTokenError();
    }
    // Step 8: lastUsedAt update with coalescing.
    const persisted = r.last_used_at ?? null;
    const shouldUpdate =
      persisted == null ||
      this.patLastUsedCoalesceSeconds === 0 ||
      Math.floor(now.getTime() / 1000) -
        Math.floor(persisted.getTime() / 1000) >=
        this.patLastUsedCoalesceSeconds;
    if (shouldUpdate) {
      await this.pool.query(
        // security-audit-v0.3.md H3: re-check revoked_at IS NULL so
        // a race with revokePat does not write last_used_at onto an
        // already-revoked row.
        `UPDATE pat SET last_used_at = $1 WHERE id = $2 AND revoked_at IS NULL`,
        [now, patUuid],
      );
    }
    return {
      patId,
      usrId: encode("usr", r.usr_id) as UsrId,
      scope: r.scope ?? [],
    };
  }

  private rowToPat(r: PatRow): PersonalAccessToken {
    const now = this.now();
    const expiresAt = r.expires_at ?? null;
    const revokedAt = r.revoked_at ?? null;
    let status: PatStatus;
    if (revokedAt != null) {
      status = "revoked";
    } else if (expiresAt != null && expiresAt <= now) {
      status = "expired";
    } else {
      status = "active";
    }
    return {
      id: encode("pat", r.id) as PatId,
      usrId: encode("usr", r.usr_id) as UsrId,
      name: r.name,
      scope: r.scope ?? [],
      status,
      expiresAt,
      lastUsedAt: r.last_used_at ?? null,
      revokedAt,
      createdAt: r.created_at,
      updatedAt: r.updated_at,
    };
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
