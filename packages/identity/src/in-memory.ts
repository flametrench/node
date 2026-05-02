// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { randomBytes, timingSafeEqual, createHash } from "node:crypto";

import { generate } from "@flametrench/ids";
import argon2 from "argon2";

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
  isStructurallyValidPatToken,
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
  type CredentialType,
  type FindCredentialInput,
  type ListOptions,
  type ListUsersOptions,
  type Page,
  type PasskeyCredential,
  type PasswordCredential,
  type OidcCredential,
  type RotateCredentialInput,
  type SesId,
  type Session,
  type Status,
  type UpdateUserInput,
  type User,
  type UsrId,
  type VerifyPasswordInput,
  type VerifiedCredentialResult,
} from "./types.js";

// ─── Internal stored shapes (include sensitive material; never leaked) ───

interface StoredPasswordCredential extends PasswordCredential {
  /** PHC-encoded Argon2id hash; never exposed in public Credential. */
  passwordHash: string;
}

interface StoredPasskeyCredential extends PasskeyCredential {
  /** COSE-encoded public key bytes; never exposed in public Credential. */
  passkeyPublicKey: Uint8Array;
}

// OIDC credentials have no sensitive per-user material, so stored === public.
type StoredOidcCredential = OidcCredential;

type StoredCredential =
  | StoredPasswordCredential
  | StoredPasskeyCredential
  | StoredOidcCredential;

function toPublicCredential(s: StoredCredential): Credential {
  // Strip sensitive fields. TS discriminated-union narrowing keeps this clean.
  if (s.type === "password") {
    const { passwordHash: _passwordHash, ...rest } = s;
    return rest;
  }
  if (s.type === "passkey") {
    const { passkeyPublicKey: _passkeyPublicKey, ...rest } = s;
    return rest;
  }
  return s;
}

/**
 * Token storage. We persist only the SHA-256 hash of the bearer token,
 * never the token itself — defence-in-depth for the in-memory store so
 * a memory dump doesn't leak bearer tokens.
 */
interface StoredSession {
  session: Session;
  tokenHash: string;
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function timingSafeStringEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return timingSafeEqual(ab, bb);
}

// ─── Options ───

export interface InMemoryIdentityStoreOptions {
  /** Override the clock for deterministic tests. Default `() => new Date()`. */
  clock?: () => Date;
  /**
   * Coalescing window for `lastUsedAt` writes on `verifyPatToken` per
   * ADR 0016 §"Operational notes". Within this window, repeat
   * verifies of the same PAT do NOT update `lastUsedAt` on the public
   * record; outside the window, the next verify updates it. 0
   * disables coalescing (always update). Default 60 seconds.
   */
  patLastUsedCoalesceSeconds?: number;
}

// ─── Store ───

export class InMemoryIdentityStore implements IdentityStore {
  private readonly users = new Map<UsrId, User>();
  private readonly credentials = new Map<CredId, StoredCredential>();
  private readonly sessions = new Map<SesId, StoredSession>();
  /** Natural-key index: `${type}|${identifier}` → credId, ACTIVE only. */
  private readonly activeCredByIdentifier = new Map<string, CredId>();
  /** Secondary index: bearer-token-hash → sesId. */
  private readonly sessionByTokenHash = new Map<string, SesId>();
  private readonly pats = new Map<PatId, PersonalAccessToken>();
  private readonly patSecretHashes = new Map<PatId, string>();
  /** patId → most recent persisted lastUsedAt; used by coalescing window. */
  private readonly patLastUsedPersisted = new Map<PatId, Date>();
  private readonly clock: () => Date;
  private readonly patLastUsedCoalesceSeconds: number;

  constructor(options: InMemoryIdentityStoreOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
    this.patLastUsedCoalesceSeconds = Math.max(
      0,
      options.patLastUsedCoalesceSeconds ?? 60,
    );
  }

  private now(): Date {
    return this.clock();
  }

  private newUsrId(): UsrId {
    return generate("usr") as UsrId;
  }
  private newCredId(): CredId {
    return generate("cred") as CredId;
  }
  private newSesId(): SesId {
    return generate("ses") as SesId;
  }

  private identifierKey(type: CredentialType, identifier: string): string {
    return `${type}|${identifier}`;
  }

  private requireUser(usrId: UsrId): User {
    const u = this.users.get(usrId);
    if (!u) throw new NotFoundError(`User ${usrId} not found`);
    return u;
  }

  private requireCredential(credId: CredId): StoredCredential {
    const c = this.credentials.get(credId);
    if (!c) throw new NotFoundError(`Credential ${credId} not found`);
    return c;
  }

  private requireSession(sesId: SesId): StoredSession {
    const s = this.sessions.get(sesId);
    if (!s) throw new NotFoundError(`Session ${sesId} not found`);
    return s;
  }

  /** Terminate every active session bound to a given credential. */
  private cascadeRevokeSessionsForCredential(credId: CredId): void {
    const now = this.now();
    for (const [sesId, entry] of this.sessions.entries()) {
      if (entry.session.credId === credId && entry.session.revokedAt === null) {
        const updated: Session = { ...entry.session, revokedAt: now };
        this.sessions.set(sesId, { ...entry, session: updated });
        this.sessionByTokenHash.delete(entry.tokenHash);
      }
    }
  }

  /** Terminate every active session belonging to a user. */
  private cascadeRevokeSessionsForUser(usrId: UsrId): void {
    const now = this.now();
    for (const [sesId, entry] of this.sessions.entries()) {
      if (entry.session.usrId === usrId && entry.session.revokedAt === null) {
        const updated: Session = { ...entry.session, revokedAt: now };
        this.sessions.set(sesId, { ...entry, session: updated });
        this.sessionByTokenHash.delete(entry.tokenHash);
      }
    }
  }

  // ─── Users ───

  async createUser(input?: CreateUserInput): Promise<User> {
    const now = this.now();
    const user: User = {
      id: this.newUsrId(),
      status: "active",
      displayName: input?.displayName ?? null,
      createdAt: now,
      updatedAt: now,
    };
    this.users.set(user.id, user);
    return user;
  }

  async getUser(usrId: UsrId): Promise<User> {
    return this.requireUser(usrId);
  }

  async updateUser(input: UpdateUserInput): Promise<User> {
    const u = this.requireUser(input.usrId);
    if (u.status === "revoked") {
      throw new AlreadyTerminalError(`User ${input.usrId} is revoked; cannot update`);
    }
    const newDisplayName = "displayName" in input ? input.displayName ?? null : u.displayName;
    if (newDisplayName === u.displayName) {
      return u;
    }
    const updated: User = { ...u, displayName: newDisplayName, updatedAt: this.now() };
    this.users.set(input.usrId, updated);
    return updated;
  }

  async listUsers(options?: ListUsersOptions): Promise<Page<User>> {
    const limit = Math.max(1, Math.min(options?.limit ?? 50, 200));
    const status = options?.status;
    const needle = options?.query?.toLowerCase() ?? null;
    const all = [...this.users.values()]
      .filter((u) => status === undefined || u.status === status)
      .filter((u) => {
        if (needle === null) return true;
        for (const cred of this.credentials.values()) {
          if (cred.usrId !== u.id) continue;
          if (cred.status !== "active") continue;
          if (cred.identifier.toLowerCase().includes(needle)) return true;
        }
        return false;
      })
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    let startIdx = 0;
    if (options?.cursor !== undefined) {
      startIdx = all.findIndex((u) => u.id > options.cursor!);
      if (startIdx === -1) startIdx = all.length;
    }
    const slice = all.slice(startIdx, startIdx + limit);
    const nextCursor =
      startIdx + limit < all.length && slice.length > 0
        ? slice[slice.length - 1]!.id
        : null;
    return { data: slice, nextCursor };
  }

  async suspendUser(usrId: UsrId): Promise<User> {
    const u = this.requireUser(usrId);
    if (u.status === "revoked") {
      throw new AlreadyTerminalError(`User ${usrId} is revoked`);
    }
    if (u.status === "suspended") {
      return u;
    }
    const now = this.now();
    const updated: User = { ...u, status: "suspended", updatedAt: now };
    this.users.set(usrId, updated);
    this.cascadeRevokeSessionsForUser(usrId);
    return updated;
  }

  async reinstateUser(usrId: UsrId): Promise<User> {
    const u = this.requireUser(usrId);
    if (u.status !== "suspended") {
      throw new PreconditionError(
        `User ${usrId} is ${u.status}; only suspended users can be reinstated`,
        "invalid_transition",
      );
    }
    const now = this.now();
    const updated: User = { ...u, status: "active", updatedAt: now };
    this.users.set(usrId, updated);
    return updated;
  }

  async revokeUser(usrId: UsrId): Promise<User> {
    const u = this.requireUser(usrId);
    if (u.status === "revoked") {
      throw new AlreadyTerminalError(`User ${usrId} is already revoked`);
    }
    const now = this.now();
    // Cascade: revoke all active credentials, terminate all sessions.
    for (const [credId, cred] of this.credentials.entries()) {
      if (cred.usrId === usrId && cred.status === "active") {
        const revoked: StoredCredential = {
          ...cred,
          status: "revoked" as Status,
          updatedAt: now,
        };
        this.credentials.set(credId, revoked);
        this.activeCredByIdentifier.delete(
          this.identifierKey(cred.type, cred.identifier),
        );
      }
    }
    this.cascadeRevokeSessionsForUser(usrId);
    const updated: User = { ...u, status: "revoked", updatedAt: now };
    this.users.set(usrId, updated);
    return updated;
  }

  // ─── Credentials ───

  async createCredential(input: CreateCredentialInput): Promise<Credential> {
    const user = this.requireUser(input.usrId);
    if (user.status !== "active") {
      throw new PreconditionError(
        `Cannot create credentials for ${user.status} user`,
        "user_not_active",
      );
    }
    const key = this.identifierKey(input.type, input.identifier);
    if (this.activeCredByIdentifier.has(key)) {
      throw new DuplicateCredentialError(
        `An active ${input.type} credential already exists for identifier ${input.identifier}`,
      );
    }
    const now = this.now();
    const id = this.newCredId();
    let stored: StoredCredential;
    switch (input.type) {
      case "password": {
        const hash = await argon2.hash(input.password, {
          type: argon2.argon2id,
          memoryCost: ARGON2ID_FLOOR.memoryCost,
          timeCost: ARGON2ID_FLOOR.timeCost,
          parallelism: ARGON2ID_FLOOR.parallelism,
        });
        stored = {
          id,
          usrId: input.usrId,
          type: "password",
          identifier: input.identifier,
          status: "active",
          replaces: null,
          createdAt: now,
          updatedAt: now,
          passwordHash: hash,
        };
        break;
      }
      case "passkey": {
        stored = {
          id,
          usrId: input.usrId,
          type: "passkey",
          identifier: input.identifier,
          status: "active",
          replaces: null,
          createdAt: now,
          updatedAt: now,
          passkeyPublicKey: input.publicKey,
          passkeySignCount: input.signCount,
          passkeyRpId: input.rpId,
        };
        break;
      }
      case "oidc": {
        stored = {
          id,
          usrId: input.usrId,
          type: "oidc",
          identifier: input.identifier,
          status: "active",
          replaces: null,
          createdAt: now,
          updatedAt: now,
          oidcIssuer: input.oidcIssuer,
          oidcSubject: input.oidcSubject,
        };
        break;
      }
    }
    this.credentials.set(id, stored);
    this.activeCredByIdentifier.set(key, id);
    return toPublicCredential(stored);
  }

  async getCredential(credId: CredId): Promise<Credential> {
    return toPublicCredential(this.requireCredential(credId));
  }

  async listCredentialsForUser(usrId: UsrId): Promise<Credential[]> {
    const results: Credential[] = [];
    for (const c of this.credentials.values()) {
      if (c.usrId === usrId) results.push(toPublicCredential(c));
    }
    return results;
  }

  async findCredentialByIdentifier(
    input: FindCredentialInput,
  ): Promise<Credential | null> {
    const credId = this.activeCredByIdentifier.get(
      this.identifierKey(input.type, input.identifier),
    );
    if (!credId) return null;
    return toPublicCredential(this.requireCredential(credId));
  }

  async rotateCredential(input: RotateCredentialInput): Promise<Credential> {
    const old = this.requireCredential(input.credId);
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
    // Revoke old.
    const revokedOld: StoredCredential = { ...old, status: "revoked", updatedAt: now };
    this.credentials.set(old.id, revokedOld);
    this.activeCredByIdentifier.delete(
      this.identifierKey(old.type, old.identifier),
    );
    // Cascade session termination.
    this.cascadeRevokeSessionsForCredential(old.id);
    // Insert new with `replaces` chain pointer.
    const newId = this.newCredId();
    let freshStored: StoredCredential;
    switch (input.type) {
      case "password": {
        const hash = await argon2.hash(input.newPassword, {
          type: argon2.argon2id,
          memoryCost: ARGON2ID_FLOOR.memoryCost,
          timeCost: ARGON2ID_FLOOR.timeCost,
          parallelism: ARGON2ID_FLOOR.parallelism,
        });
        freshStored = {
          id: newId,
          usrId: old.usrId,
          type: "password",
          identifier: old.identifier,
          status: "active",
          replaces: old.id,
          createdAt: now,
          updatedAt: now,
          passwordHash: hash,
        };
        break;
      }
      case "passkey": {
        freshStored = {
          id: newId,
          usrId: old.usrId,
          type: "passkey",
          identifier: old.identifier,
          status: "active",
          replaces: old.id,
          createdAt: now,
          updatedAt: now,
          passkeyPublicKey: input.publicKey,
          passkeySignCount: input.signCount,
          passkeyRpId: input.rpId,
        };
        break;
      }
      case "oidc": {
        freshStored = {
          id: newId,
          usrId: old.usrId,
          type: "oidc",
          identifier: old.identifier,
          status: "active",
          replaces: old.id,
          createdAt: now,
          updatedAt: now,
          oidcIssuer: input.oidcIssuer,
          oidcSubject: input.oidcSubject,
        };
        break;
      }
    }
    this.credentials.set(newId, freshStored);
    this.activeCredByIdentifier.set(
      this.identifierKey(old.type, old.identifier),
      newId,
    );
    return toPublicCredential(freshStored);
  }

  async suspendCredential(credId: CredId): Promise<Credential> {
    const c = this.requireCredential(credId);
    if (c.status !== "active") {
      throw new PreconditionError(
        `Credential ${credId} is ${c.status}; only active credentials can be suspended`,
        "cred_not_active",
      );
    }
    const now = this.now();
    const updated: StoredCredential = { ...c, status: "suspended", updatedAt: now };
    this.credentials.set(credId, updated);
    this.activeCredByIdentifier.delete(this.identifierKey(c.type, c.identifier));
    this.cascadeRevokeSessionsForCredential(credId);
    return toPublicCredential(updated);
  }

  async reinstateCredential(credId: CredId): Promise<Credential> {
    const c = this.requireCredential(credId);
    if (c.status !== "suspended") {
      throw new PreconditionError(
        `Credential ${credId} is ${c.status}; only suspended credentials can be reinstated`,
        "invalid_transition",
      );
    }
    const key = this.identifierKey(c.type, c.identifier);
    if (this.activeCredByIdentifier.has(key)) {
      throw new DuplicateCredentialError(
        `Another active ${c.type} credential already exists for ${c.identifier}; cannot reinstate`,
      );
    }
    const now = this.now();
    const updated: StoredCredential = { ...c, status: "active", updatedAt: now };
    this.credentials.set(credId, updated);
    this.activeCredByIdentifier.set(key, credId);
    return toPublicCredential(updated);
  }

  async revokeCredential(credId: CredId): Promise<Credential> {
    const c = this.requireCredential(credId);
    if (c.status === "revoked") {
      throw new AlreadyTerminalError(`Credential ${credId} is already revoked`);
    }
    const now = this.now();
    const updated: StoredCredential = { ...c, status: "revoked", updatedAt: now };
    this.credentials.set(credId, updated);
    this.activeCredByIdentifier.delete(this.identifierKey(c.type, c.identifier));
    this.cascadeRevokeSessionsForCredential(credId);
    return toPublicCredential(updated);
  }

  async verifyPassword(input: VerifyPasswordInput): Promise<VerifiedCredentialResult> {
    const credId = this.activeCredByIdentifier.get(
      this.identifierKey("password", input.identifier),
    );
    if (!credId) {
      throw new InvalidCredentialError(`Invalid credential`);
    }
    const cred = this.requireCredential(credId);
    if (cred.type !== "password") {
      // Shouldn't happen — the natural-key index is type-scoped — but keep
      // the invariant defensive.
      throw new InvalidCredentialError(`Invalid credential`);
    }
    const stored = cred as StoredPasswordCredential;
    const ok = await argon2.verify(stored.passwordHash, input.password);
    if (!ok) {
      throw new InvalidCredentialError(`Invalid credential`);
    }
    // ADR 0008: surface usr_mfa_policy state.
    const policy = this.mfaPolicies.get(cred.usrId);
    let mfaRequired = false;
    if (policy?.required) {
      if (policy.graceUntil === null || policy.graceUntil <= this.now()) {
        mfaRequired = true;
      }
    }
    return { usrId: cred.usrId, credId: cred.id, mfaRequired };
  }

  // ─── Sessions ───

  private generateToken(): string {
    return randomBytes(32).toString("base64url");
  }

  async createSession(input: CreateSessionInput): Promise<CreateSessionResult> {
    const user = this.requireUser(input.usrId);
    if (user.status !== "active") {
      throw new PreconditionError(
        `Cannot create session for ${user.status} user`,
        "user_not_active",
      );
    }
    const cred = this.requireCredential(input.credId);
    if (cred.status !== "active") {
      throw new CredentialNotActiveError(
        `Credential ${input.credId} is ${cred.status}`,
      );
    }
    if (cred.usrId !== input.usrId) {
      throw new PreconditionError(
        `Credential ${input.credId} does not belong to ${input.usrId}`,
        "cred_user_mismatch",
      );
    }
    if (input.ttlSeconds < 60) {
      throw new PreconditionError(
        `ttlSeconds must be >= 60`,
        "ttl_too_short",
      );
    }
    const now = this.now();
    const token = this.generateToken();
    const tokenHash = hashToken(token);
    const session: Session = {
      id: this.newSesId(),
      usrId: input.usrId,
      credId: input.credId,
      createdAt: now,
      expiresAt: new Date(now.getTime() + input.ttlSeconds * 1000),
      revokedAt: null,
    };
    this.sessions.set(session.id, { session, tokenHash });
    this.sessionByTokenHash.set(tokenHash, session.id);
    return { session, token };
  }

  async getSession(sesId: SesId): Promise<Session> {
    return this.requireSession(sesId).session;
  }

  async listSessionsForUser(
    usrId: UsrId,
    options: ListOptions = {},
  ): Promise<Page<Session>> {
    const all = [...this.sessions.values()]
      .map((s) => s.session)
      .filter((s) => s.usrId === usrId)
      .sort((a, b) => a.id.localeCompare(b.id));
    const limit = options.limit ?? 50;
    const startIndex = options.cursor
      ? all.findIndex((x) => x.id > options.cursor!)
      : 0;
    const start = startIndex < 0 ? all.length : startIndex;
    const data = all.slice(start, start + limit);
    const nextCursor =
      start + limit < all.length ? (data[data.length - 1]?.id ?? null) : null;
    return { data, nextCursor };
  }

  async verifySessionToken(token: string): Promise<Session> {
    const tokenHash = hashToken(token);
    const sesId = this.sessionByTokenHash.get(tokenHash);
    if (!sesId) throw new InvalidTokenError(`Invalid token`);
    const entry = this.requireSession(sesId);
    if (!timingSafeStringEqual(tokenHash, entry.tokenHash)) {
      throw new InvalidTokenError(`Invalid token`);
    }
    if (entry.session.revokedAt !== null) {
      throw new SessionExpiredError(`Session is revoked`);
    }
    if (this.now().getTime() > entry.session.expiresAt.getTime()) {
      throw new SessionExpiredError(`Session has expired`);
    }
    return entry.session;
  }

  async refreshSession(sesId: SesId): Promise<CreateSessionResult> {
    const entry = this.requireSession(sesId);
    if (entry.session.revokedAt !== null) {
      throw new SessionExpiredError(`Session is already revoked`);
    }
    if (this.now().getTime() > entry.session.expiresAt.getTime()) {
      throw new SessionExpiredError(`Session has expired`);
    }
    const now = this.now();
    // Revoke old session.
    const revokedSession: Session = { ...entry.session, revokedAt: now };
    this.sessions.set(sesId, { ...entry, session: revokedSession });
    this.sessionByTokenHash.delete(entry.tokenHash);

    // Create new session with same credential and a fresh TTL matching the
    // original session's TTL (expiresAt - createdAt window).
    const originalTtlMs = entry.session.expiresAt.getTime() - entry.session.createdAt.getTime();
    const token = this.generateToken();
    const tokenHash = hashToken(token);
    const fresh: Session = {
      id: this.newSesId(),
      usrId: entry.session.usrId,
      credId: entry.session.credId,
      createdAt: now,
      expiresAt: new Date(now.getTime() + originalTtlMs),
      revokedAt: null,
    };
    this.sessions.set(fresh.id, { session: fresh, tokenHash });
    this.sessionByTokenHash.set(tokenHash, fresh.id);
    return { session: fresh, token };
  }

  async revokeSession(sesId: SesId): Promise<Session> {
    const entry = this.requireSession(sesId);
    if (entry.session.revokedAt !== null) {
      return entry.session;
    }
    const now = this.now();
    const updated: Session = { ...entry.session, revokedAt: now };
    this.sessions.set(sesId, { ...entry, session: updated });
    this.sessionByTokenHash.delete(entry.tokenHash);
    return updated;
  }

  // ─── v0.2 MFA store operations (ADR 0008) ──────────────────────

  /** Pending TOTP/WebAuthn factor TTL per ADR 0008. */
  static readonly PENDING_FACTOR_TTL_SECONDS = 600;

  private mfaFactors = new Map<string, Factor>();
  private mfaTotpSecrets = new Map<string, Uint8Array>();
  private mfaWebauthnKeys = new Map<string, Uint8Array>();
  private mfaRecoveryHashes = new Map<string, string[]>();
  private mfaRecoveryConsumed = new Map<string, boolean[]>();
  /** Singleton index for at-most-one-active TOTP/recovery per user. */
  private mfaActiveSingleton = new Map<string, string>(); // `${usrId}|${type}` → mfaId
  private mfaWebauthnByCredentialId = new Map<string, string>();
  private mfaPolicies = new Map<string, UserMfaPolicy>();

  private requireFactor(mfaId: string): Factor {
    const f = this.mfaFactors.get(mfaId);
    if (!f) throw new NotFoundError(`MFA factor ${mfaId} not found`);
    return f;
  }

  private checkUserActive(usrId: UsrId): void {
    const user = this.users.get(usrId);
    if (!user) throw new NotFoundError(`User ${usrId} not found`);
    if (user.status !== "active") {
      throw new PreconditionError(
        `User ${usrId} is ${user.status}; cannot enroll MFA`,
        "user_not_active",
      );
    }
  }

  private enforceNoActiveSingleton(usrId: UsrId, type: "totp" | "recovery"): void {
    const key = `${usrId}|${type}`;
    if (this.mfaActiveSingleton.has(key)) {
      throw new PreconditionError(
        `User ${usrId} already has an active ${type} factor; revoke before re-enrolling`,
        "active_singleton_exists",
      );
    }
  }

  private checkPendingNotExpired(factor: Factor): void {
    if (factor.status !== "pending") return;
    const ageSec = (this.now().getTime() - factor.createdAt.getTime()) / 1000;
    if (ageSec > InMemoryIdentityStore.PENDING_FACTOR_TTL_SECONDS) {
      throw new PreconditionError(
        `Pending factor ${factor.id} expired ` +
          `(${ageSec.toFixed(0)}s > ${InMemoryIdentityStore.PENDING_FACTOR_TTL_SECONDS}s)`,
        "pending_factor_expired",
      );
    }
  }

  async enrollTotpFactor(
    usrId: UsrId,
    identifier: string,
  ): Promise<TotpEnrollmentResult> {
    this.checkUserActive(usrId);
    this.enforceNoActiveSingleton(usrId, "totp");
    const now = this.now();
    const secret = generateTotpSecret();
    const mfaId = generate("mfa") as `mfa_${string}`;
    const factor: TotpFactor = {
      type: "totp",
      id: mfaId,
      usrId,
      identifier,
      status: "pending",
      replaces: null,
      createdAt: now,
      updatedAt: now,
    };
    this.mfaFactors.set(mfaId, factor);
    this.mfaTotpSecrets.set(mfaId, secret);
    const secretB32 = Buffer.from(secret)
      .toString("base64")
      .replace(/=+$/, "")
      // Convert RFC 4648 base64 (used by Buffer) to base32 — re-encode
      // via a standard helper so the otpauth URI matches.
      .toUpperCase();
    // The Python helper produces a true base32; do the same here.
    const properBase32 = base32Encode(secret);
    return {
      factor,
      secretB32: properBase32,
      otpauthUri: totpOtpauthUri({
        secret,
        label: identifier,
        issuer: "Flametrench",
      }),
    };
  }

  async enrollWebAuthnFactor(
    input: EnrollWebAuthnFactorInput,
  ): Promise<WebAuthnEnrollmentResult> {
    this.checkUserActive(input.usrId);
    if (this.mfaWebauthnByCredentialId.has(input.identifier)) {
      throw new PreconditionError(
        `WebAuthn credential ${JSON.stringify(input.identifier)} is already enrolled`,
        "duplicate_webauthn_credential",
      );
    }
    const now = this.now();
    const mfaId = generate("mfa") as `mfa_${string}`;
    const factor: WebAuthnFactor = {
      type: "webauthn",
      id: mfaId,
      usrId: input.usrId,
      identifier: input.identifier,
      status: "pending",
      replaces: null,
      rpId: input.rpId,
      signCount: input.signCount,
      createdAt: now,
      updatedAt: now,
    };
    this.mfaFactors.set(mfaId, factor);
    this.mfaWebauthnKeys.set(mfaId, input.publicKey);
    this.mfaWebauthnByCredentialId.set(input.identifier, mfaId);
    return { factor };
  }

  async enrollRecoveryFactor(usrId: UsrId): Promise<RecoveryEnrollmentResult> {
    this.checkUserActive(usrId);
    this.enforceNoActiveSingleton(usrId, "recovery");
    const now = this.now();
    const codes = generateRecoveryCodes();
    const hashes = await Promise.all(codes.map((c) => hashPassword(c)));
    const consumed = codes.map(() => false);
    const mfaId = generate("mfa") as `mfa_${string}`;
    const factor: RecoveryFactor = {
      type: "recovery",
      id: mfaId,
      usrId,
      status: "active",
      replaces: null,
      createdAt: now,
      updatedAt: now,
      remaining: codes.length,
    };
    this.mfaFactors.set(mfaId, factor);
    this.mfaRecoveryHashes.set(mfaId, hashes);
    this.mfaRecoveryConsumed.set(mfaId, consumed);
    this.mfaActiveSingleton.set(`${usrId}|recovery`, mfaId);
    return { factor, codes };
  }

  async getMfaFactor(mfaId: string): Promise<Factor> {
    return this.requireFactor(mfaId);
  }

  async listMfaFactors(usrId: UsrId): Promise<Factor[]> {
    return Array.from(this.mfaFactors.values()).filter(
      (f) => f.usrId === usrId,
    );
  }

  async confirmTotpFactor(mfaId: string, code: string): Promise<TotpFactor> {
    const factor = this.requireFactor(mfaId);
    if (factor.type !== "totp") {
      throw new CredentialTypeMismatchError(
        `Factor ${mfaId} is ${factor.type}, not totp`,
      );
    }
    if (factor.status !== "pending") {
      throw new PreconditionError(
        `Factor ${mfaId} is ${factor.status}; only pending factors confirm`,
        "factor_not_pending",
      );
    }
    this.checkPendingNotExpired(factor);
    const secret = this.mfaTotpSecrets.get(mfaId)!;
    const ok = totpVerify(secret, code, {
      timestamp: Math.floor(this.now().getTime() / 1000),
    });
    if (!ok) {
      throw new InvalidCredentialError("TOTP code did not verify");
    }
    const now = this.now();
    const active: TotpFactor = { ...factor, status: "active", updatedAt: now };
    this.mfaFactors.set(mfaId, active);
    this.mfaActiveSingleton.set(`${factor.usrId}|totp`, mfaId);
    return active;
  }

  async confirmWebAuthnFactor(
    input: ConfirmWebAuthnFactorInput,
  ): Promise<WebAuthnFactor> {
    const factor = this.requireFactor(input.mfaId);
    if (factor.type !== "webauthn") {
      throw new CredentialTypeMismatchError(
        `Factor ${input.mfaId} is ${factor.type}, not webauthn`,
      );
    }
    if (factor.status !== "pending") {
      throw new PreconditionError(
        `Factor ${input.mfaId} is ${factor.status}; only pending factors confirm`,
        "factor_not_pending",
      );
    }
    this.checkPendingNotExpired(factor);
    const result = webauthnVerifyAssertion({
      cosePublicKey: this.mfaWebauthnKeys.get(input.mfaId)!,
      storedSignCount: factor.signCount,
      storedRpId: factor.rpId,
      expectedChallenge: input.expectedChallenge,
      expectedOrigin: input.expectedOrigin,
      authenticatorData: input.authenticatorData,
      clientDataJson: input.clientDataJson,
      signature: input.signature,
    });
    const now = this.now();
    const active: WebAuthnFactor = {
      ...factor,
      status: "active",
      signCount: result.newSignCount,
      updatedAt: now,
    };
    this.mfaFactors.set(input.mfaId, active);
    return active;
  }

  async revokeMfaFactor(mfaId: string): Promise<Factor> {
    const factor = this.requireFactor(mfaId);
    if (factor.status === "revoked") return factor;
    const now = this.now();
    const revoked = { ...factor, status: "revoked" as const, updatedAt: now };
    this.mfaFactors.set(mfaId, revoked);
    if (factor.type === "totp") {
      this.mfaActiveSingleton.delete(`${factor.usrId}|totp`);
    } else if (factor.type === "recovery") {
      this.mfaActiveSingleton.delete(`${factor.usrId}|recovery`);
    } else if (factor.type === "webauthn") {
      this.mfaWebauthnByCredentialId.delete(factor.identifier);
    }
    return revoked;
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
    const mfaId = this.mfaActiveSingleton.get(`${usrId}|totp`);
    if (!mfaId) throw new InvalidCredentialError("No active TOTP factor for user");
    const secret = this.mfaTotpSecrets.get(mfaId)!;
    const ok = totpVerify(secret, code, {
      timestamp: Math.floor(this.now().getTime() / 1000),
    });
    if (!ok) throw new InvalidCredentialError("TOTP code did not verify");
    return {
      mfaId,
      type: "totp",
      mfaVerifiedAt: this.now(),
      newSignCount: null,
    };
  }

  private async verifyWebAuthnProof(
    usrId: UsrId,
    proof: WebAuthnProof,
  ): Promise<MfaVerifyResult> {
    const mfaId = this.mfaWebauthnByCredentialId.get(proof.credentialId);
    if (!mfaId) {
      throw new InvalidCredentialError("No WebAuthn factor for credential id");
    }
    const factor = this.mfaFactors.get(mfaId);
    if (!factor || factor.type !== "webauthn") {
      throw new InvalidCredentialError("Factor is not WebAuthn");
    }
    if (factor.usrId !== usrId) {
      // Generic — don't leak which user owns the credential.
      throw new InvalidCredentialError("WebAuthn factor does not belong to user");
    }
    if (factor.status !== "active") {
      throw new InvalidCredentialError(
        `WebAuthn factor is ${factor.status}, not active`,
      );
    }
    const result = webauthnVerifyAssertion({
      cosePublicKey: this.mfaWebauthnKeys.get(mfaId)!,
      storedSignCount: factor.signCount,
      storedRpId: factor.rpId,
      expectedChallenge: proof.expectedChallenge,
      expectedOrigin: proof.expectedOrigin,
      authenticatorData: proof.authenticatorData,
      clientDataJson: proof.clientDataJson,
      signature: proof.signature,
    });
    const now = this.now();
    const updated: WebAuthnFactor = {
      ...factor,
      signCount: result.newSignCount,
      updatedAt: now,
    };
    this.mfaFactors.set(mfaId, updated);
    return {
      mfaId,
      type: "webauthn",
      mfaVerifiedAt: now,
      newSignCount: result.newSignCount,
    };
  }

  private async verifyRecoveryProof(
    usrId: UsrId,
    code: string,
  ): Promise<MfaVerifyResult> {
    const mfaId = this.mfaActiveSingleton.get(`${usrId}|recovery`);
    if (!mfaId) {
      throw new InvalidCredentialError("No active recovery factor for user");
    }
    const normalized = normalizeRecoveryInput(code);
    if (!isValidRecoveryCode(normalized)) {
      throw new InvalidCredentialError("Recovery code is malformed");
    }
    const hashes = this.mfaRecoveryHashes.get(mfaId)!;
    const consumed = this.mfaRecoveryConsumed.get(mfaId)!;
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
    const factor = this.mfaFactors.get(mfaId);
    if (factor && factor.type === "recovery") {
      const remaining = consumed.filter((c) => !c).length;
      this.mfaFactors.set(mfaId, {
        ...factor,
        remaining,
        updatedAt: this.now(),
      });
    }
    return {
      mfaId,
      type: "recovery",
      mfaVerifiedAt: this.now(),
      newSignCount: null,
    };
  }

  async getMfaPolicy(usrId: UsrId): Promise<UserMfaPolicy | null> {
    if (!this.users.has(usrId)) {
      throw new NotFoundError(`User ${usrId} not found`);
    }
    return this.mfaPolicies.get(usrId) ?? null;
  }

  async setMfaPolicy(input: SetMfaPolicyInput): Promise<UserMfaPolicy> {
    if (!this.users.has(input.usrId)) {
      throw new NotFoundError(`User ${input.usrId} not found`);
    }
    const policy: UserMfaPolicy = {
      usrId: input.usrId,
      required: input.required,
      graceUntil: input.graceUntil ?? null,
      updatedAt: this.now(),
    };
    this.mfaPolicies.set(input.usrId, policy);
    return policy;
  }

  // ─── v0.3 personal access tokens (ADR 0016) ───

  async createPat(input: CreatePatInput): Promise<CreatePatResult> {
    const user = this.users.get(input.usrId);
    if (!user) throw new NotFoundError(`User ${input.usrId} not found`);
    if (user.status === "revoked") {
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
    const patId = generate("pat") as PatId;
    const idHexSegment = patId.slice(4); // strip "pat_" → 32 hex
    const secretBytes = randomBytes(32);
    const secretSegment = base64UrlEncode(secretBytes);
    const token = `pat_${idHexSegment}_${secretSegment}`;
    const secretHash = await hashPassword(secretSegment);

    const pat: PersonalAccessToken = {
      id: patId,
      usrId: input.usrId,
      name: input.name,
      scope: [...input.scope],
      status: "active",
      expiresAt: input.expiresAt ?? null,
      lastUsedAt: null,
      revokedAt: null,
      createdAt: now,
      updatedAt: now,
    };
    this.pats.set(patId, pat);
    this.patSecretHashes.set(patId, secretHash);
    return { pat, token };
  }

  async getPat(patId: PatId): Promise<PersonalAccessToken> {
    const pat = this.pats.get(patId);
    if (!pat) throw new NotFoundError(`PAT ${patId} not found`);
    return this.withDerivedStatus(pat);
  }

  async listPatsForUser(
    usrId: UsrId,
    options: ListPatsForUserOptions = {},
  ): Promise<Page<PersonalAccessToken>> {
    const limit = Math.max(1, Math.min(options.limit ?? 50, 200));
    const matching: PersonalAccessToken[] = [];
    for (const pat of this.pats.values()) {
      if (pat.usrId !== usrId) continue;
      const derived = this.withDerivedStatus(pat);
      if (options.status != null && derived.status !== options.status) continue;
      matching.push(derived);
    }
    matching.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    let startIdx = 0;
    if (options.cursor != null) {
      for (let i = 0; i < matching.length; i++) {
        if (matching[i]!.id > options.cursor) {
          startIdx = i;
          break;
        }
        startIdx = i + 1;
      }
    }
    const slice = matching.slice(startIdx, startIdx + limit);
    const nextCursor =
      startIdx + limit < matching.length && slice.length > 0
        ? slice[slice.length - 1]!.id
        : null;
    return { data: slice, nextCursor };
  }

  async revokePat(patId: PatId): Promise<PersonalAccessToken> {
    const pat = this.pats.get(patId);
    if (!pat) throw new NotFoundError(`PAT ${patId} not found`);
    // Idempotent: already revoked → return existing.
    if (pat.revokedAt != null) return this.withDerivedStatus(pat);
    const now = this.now();
    const updated: PersonalAccessToken = {
      ...pat,
      status: "revoked",
      revokedAt: now,
      updatedAt: now,
    };
    this.pats.set(patId, updated);
    return updated;
  }

  async verifyPatToken(token: string): Promise<VerifiedPat> {
    // Step 1–2: structural decode. Per ADR 0016 the format is
    // pat_<32hex>_<base64url-secret>. security-audit-v0.3.md L3:
    // delegate the structural check to the canonical helper rather
    // than re-implementing it here — the helper drives the spec
    // conformance fixture so any drift surfaces immediately.
    if (!isStructurallyValidPatToken(token)) {
      throw new InvalidPatTokenError();
    }
    const idHex = token.slice(4, 36);
    const secretSegment = token.slice(37);
    // security-audit-v0.3.md H6: cap on secret-segment length so an
    // attacker with a known pat_id cannot force unbounded Argon2id
    // work by submitting MB-sized secrets. Real PAT secrets are 43
    // chars (32 random bytes base64url-encoded); 256 is generous.
    if (secretSegment.length > PAT_MAX_SECRET_LENGTH) {
      throw new InvalidPatTokenError();
    }
    const patId = `pat_${idHex}` as PatId;

    // Step 3–4: lookup; conflate "no row" with "wrong secret".
    // security-audit-v0.3.md H2: when the row is missing we still
    // perform an Argon2id verify against a dummy hash so the
    // wall-clock time of the missing-row path matches the
    // row-exists-but-wrong-secret path. Without this, an attacker
    // can probe pat_id existence via timing without ever knowing
    // the secret. The dummy PHC hash is the same one used in the
    // argon2id.json conformance fixture — known-good, generated
    // with the spec floor parameters, will never match a real
    // 43-char base64url PAT secret.
    const pat = this.pats.get(patId);
    if (!pat) {
      await verifyPasswordHash(PAT_DUMMY_PHC_HASH, secretSegment);
      throw new InvalidPatTokenError();
    }

    // Step 5: revoked terminal check.
    if (pat.revokedAt != null) throw new PatRevokedError(patId);
    // Step 6: expiry.
    const now = this.now();
    if (pat.expiresAt != null && pat.expiresAt <= now) {
      throw new PatExpiredError(patId);
    }
    // Step 7: Argon2id verify; conflated error shape.
    const hash = this.patSecretHashes.get(patId);
    if (hash == null || !(await verifyPasswordHash(hash, secretSegment))) {
      throw new InvalidPatTokenError();
    }
    // Step 8: lastUsedAt update with coalescing.
    const persisted = this.patLastUsedPersisted.get(patId) ?? null;
    const shouldUpdate =
      persisted == null ||
      this.patLastUsedCoalesceSeconds === 0 ||
      Math.floor(now.getTime() / 1000) - Math.floor(persisted.getTime() / 1000) >=
        this.patLastUsedCoalesceSeconds;
    if (shouldUpdate) {
      this.pats.set(patId, { ...pat, lastUsedAt: now, updatedAt: now });
      this.patLastUsedPersisted.set(patId, now);
    }
    return { patId, usrId: pat.usrId, scope: [...pat.scope] };
  }

  /**
   * Derive the public `status` from lifecycle columns. The persisted
   * status is what was set at write time; reads always re-derive so a
   * row that crossed its expiresAt without being touched still reports
   * "expired" to the caller.
   */
  private withDerivedStatus(pat: PersonalAccessToken): PersonalAccessToken {
    let derived: PatStatus;
    if (pat.revokedAt != null) {
      derived = "revoked";
    } else if (pat.expiresAt != null && pat.expiresAt <= this.now()) {
      derived = "expired";
    } else {
      derived = "active";
    }
    if (derived === pat.status) return pat;
    return { ...pat, status: derived };
  }
}

/** RFC 4648 §5 base64url, no padding. Matches the spec wire format. */
function base64UrlEncode(buf: Uint8Array): string {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** Inline RFC 4648 base32 — the Python SDK uses base64.b32encode for the otpauth URI. */
function base32Encode(buf: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of buf) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += alphabet[(value << (5 - bits)) & 0x1f];
  }
  return out;
}
