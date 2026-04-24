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
  InvalidTokenError,
  NotFoundError,
  PreconditionError,
  SessionExpiredError,
} from "./errors.js";
import type { IdentityStore } from "./store.js";
import {
  ARGON2ID_FLOOR,
  type CreateCredentialInput,
  type CreateSessionInput,
  type CreateSessionResult,
  type CredId,
  type Credential,
  type CredentialType,
  type FindCredentialInput,
  type ListOptions,
  type Page,
  type PasskeyCredential,
  type PasswordCredential,
  type OidcCredential,
  type RotateCredentialInput,
  type SesId,
  type Session,
  type Status,
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
  private readonly clock: () => Date;

  constructor(options: InMemoryIdentityStoreOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
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

  async createUser(): Promise<User> {
    const now = this.now();
    const user: User = {
      id: this.newUsrId(),
      status: "active",
      createdAt: now,
      updatedAt: now,
    };
    this.users.set(user.id, user);
    return user;
  }

  async getUser(usrId: UsrId): Promise<User> {
    return this.requireUser(usrId);
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
    return { usrId: cred.usrId, credId: cred.id };
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
}
