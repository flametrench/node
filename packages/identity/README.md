# @flametrench/identity

Identity primitives for [Flametrench](https://flametrench.dev): users, credentials (password, passkey, OIDC), and user-bound sessions. Spec-conformant — Argon2id-pinned password hashing, revoke-and-re-add credential rotation, rotation-on-refresh sessions, and comprehensive cascade semantics. v0.2 adds first-class multi-factor authentication ([ADR 0008](https://github.com/flametrench/spec/blob/main/decisions/0008-mfa.md), [ADR 0010](https://github.com/flametrench/spec/blob/main/decisions/0010-webauthn-rs256-eddsa.md)) — TOTP (RFC 6238), recovery codes, and WebAuthn assertion verification across ES256 / RS256 / EdDSA.

**Status:** v0.2.0-rc.4 (release candidate). Includes the production-ready `PostgresIdentityStore` alongside the in-memory reference store.

## Install

```bash
pnpm add @flametrench/identity
```

## Quick start

```ts
import { InMemoryIdentityStore } from "@flametrench/identity";

const store = new InMemoryIdentityStore();

// Create a user and a password credential.
const user = await store.createUser();
const cred = await store.createCredential({
  usrId: user.id,
  type: "password",
  identifier: "alice@example.com",
  password: "correcthorsebatterystaple",
});

// Verify the password and open a session.
const verified = await store.verifyPassword({
  type: "password",
  identifier: "alice@example.com",
  password: "correcthorsebatterystaple",
});
const { session, token } = await store.createSession({
  usrId: verified.usrId,
  credId: verified.credId,
  ttlSeconds: 3600,
});

// Later, verify an incoming bearer token.
const live = await store.verifySessionToken(token);
console.log(live.id === session.id); // true
```

## Credential types

| Type | Sensitive-at-rest material | Verification |
|---|---|---|
| `password` | Argon2id PHC hash | Handled by this package via `verifyPassword()`. Parameters are pinned at or above the spec floor: `m=19456, t=2, p=1`. |
| `passkey` | WebAuthn public key bytes | Stored as a `cred_` for password-less login; verified at sign-in by the caller (or via the v0.2 `mfa_` factor type when the same passkey is bound as a second factor). |
| `oidc` | None per-user (issuer + subject claim) | Verification of the ID token is the caller's responsibility; this package stores the issuer/subject pair so `findCredentialByIdentifier` returns the correct `usr_id` after the caller has verified. |

## API shape

Every backend implements the `IdentityStore` interface:

```ts
interface IdentityStore {
  // Users
  createUser(): Promise<User>;
  getUser(usrId): Promise<User>;
  suspendUser / reinstateUser / revokeUser(usrId): Promise<User>;

  // Credentials
  createCredential(input): Promise<Credential>;
  getCredential(credId): Promise<Credential>;
  listCredentialsForUser(usrId): Promise<Credential[]>;
  findCredentialByIdentifier(input): Promise<Credential | null>;
  rotateCredential(input): Promise<Credential>;           // revoke + re-add
  suspendCredential / reinstateCredential / revokeCredential(credId): Promise<Credential>;
  verifyPassword(input): Promise<VerifiedCredentialResult>;

  // Sessions
  createSession(input): Promise<CreateSessionResult>;     // returns session + opaque token
  getSession(sesId): Promise<Session>;
  listSessionsForUser(usrId, options?): Promise<Page<Session>>;
  verifySessionToken(token): Promise<Session>;
  refreshSession(sesId): Promise<CreateSessionResult>;    // rotates: new id + new token
  revokeSession(sesId): Promise<Session>;
}
```

## Session tokens vs. session IDs

Per the spec (ADR 0004, `docs/identity.md`), the session `id` is an **identifier** — it may appear in logs, admin panels, audit queries. The bearer **token** is a separate, opaque value (32 random bytes, base64url-encoded) that clients pass in `Authorization: Bearer`. This package stores only the SHA-256 hash of the token; the plaintext token is returned exactly once (from `createSession` / `refreshSession`) and never leaves the caller's memory via this SDK.

Implementations that prefer signed-JWT tokens instead of opaque-server-looked-up tokens are spec-conformant; this package happens to use opaque tokens because it's the simpler and more uniformly revocable option.

## Cascade semantics (spec-required)

- **Revoking a user** revokes every active credential owned by that user AND terminates every active session.
- **Suspending a user** terminates every active session but leaves credentials alone (the user can be reinstated and their creds still work).
- **Rotating a credential** terminates every session that was established by the pre-rotation credential. The new credential starts with zero active sessions.
- **Revoking a credential** terminates every session bound to it.
- **Suspending a credential** terminates every session bound to it (sessions don't survive the credential being unavailable).

Every cascade is maintained atomically by the store; tests include explicit fixtures for each.

## Errors

Every error is an `IdentityError` with a stable machine-readable `code`:

| Class | Code | When |
|---|---|---|
| `NotFoundError` | `not_found` | Referenced user, credential, or session does not exist. |
| `DuplicateCredentialError` | `conflict.duplicate_credential` | An active credential with the same `(type, identifier)` already exists. |
| `InvalidCredentialError` | `unauthorized.invalid_credential` | `verifyPassword` received a wrong password or unknown identifier. Constant-time equivalent. |
| `CredentialNotActiveError` | `conflict.credential_not_active` | Operation requires the credential to be active but it is suspended or revoked. |
| `CredentialTypeMismatchError` | `conflict.credential_type_mismatch` | `rotateCredential` called with a payload of a different type. |
| `SessionExpiredError` | `unauthorized.session_expired` | Session has passed its expiry or been revoked. |
| `InvalidTokenError` | `unauthorized.invalid_token` | Bearer token does not correspond to any known session. |
| `AlreadyTerminalError` | `conflict.already_terminal` | Target entity is in a terminal state (revoked) and cannot transition further. |
| `PreconditionError` | `precondition.<specifics>` | A specific operation precondition was not met. |

## Development

```bash
pnpm install
pnpm -r build
pnpm -r test        # includes @flametrench/identity's 30 unit tests
```

## Shipped in v0.2 RC

- `PostgresIdentityStore` at `@flametrench/identity/postgres` — production-ready, mirrors the in-memory reference store byte-for-byte at the SDK boundary.
- First-class multi-factor authentication ([ADR 0008](https://github.com/flametrench/spec/blob/main/decisions/0008-mfa.md)): TOTP (RFC 6238), recovery codes, and WebAuthn assertion verification.
- WebAuthn algorithm coverage extended to ES256 + RS256 + EdDSA ([ADR 0010](https://github.com/flametrench/spec/blob/main/decisions/0010-webauthn-rs256-eddsa.md)).

## Not yet shipped

- First-class OIDC issuer metadata discovery and ID-token verification (caller still verifies the ID token; this package stores the issuer/subject pair).
- Magic-link and SAML credential types — deferred to v0.3+.

## License

Apache License 2.0. Copyright 2026 NDC Digital, LLC.
