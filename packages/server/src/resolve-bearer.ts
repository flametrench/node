// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Bearer-token prefix dispatcher (ADR 0016).
 *
 * v0.3 broadens what `Authorization: Bearer` may carry: session tokens
 * (v0.1), share tokens (v0.2 / ADR 0012), and personal access tokens
 * (v0.3 / ADR 0016). This helper inspects the token prefix and
 * dispatches to the matching verifier on the supplied stores.
 *
 * Bearer types do not overlap by design — verifiers MUST NOT attempt
 * cross-form decoding (e.g. trying a `pat_…` string against the
 * session resolver). Mis-routing returns a structured error with the
 * stable `auth.token_format_unrecognized` code.
 *
 * Adopters that have not yet adopted PATs or shares can omit those
 * stores; tokens with the corresponding prefix then fail with
 * `auth.token_format_unrecognized` instead of being routed to a
 * verifier that doesn't exist.
 *
 * The result's `kind` field is the canonical `auth.kind` audit
 * discriminator value (per ADR 0016): `"session" | "pat" | "share"`.
 * Adopters that emit audit records SHOULD populate `auth.kind` from
 * this field. (`"system"` — operator-initiated, no human bearer — is
 * also a valid `auth.kind` value but is never minted by this helper;
 * it's set directly by adopter code.)
 */

import type { IdentityStore, VerifiedPat } from "@flametrench/identity";
import type { ShareStore, VerifiedShare } from "@flametrench/authz";

/** Stable error code for tokens that don't match any registered prefix. */
export const TOKEN_FORMAT_UNRECOGNIZED_CODE = "auth.token_format_unrecognized";

export class TokenFormatUnrecognizedError extends Error {
  public readonly code = TOKEN_FORMAT_UNRECOGNIZED_CODE;

  constructor(message: string = "bearer token prefix is not recognized") {
    super(message);
    this.name = "TokenFormatUnrecognizedError";
  }
}

/** Successful resolution of a bearer token. */
export type ResolvedBearer =
  | {
      kind: "session";
      /** The session record returned by `verifySessionToken`. */
      session: Awaited<ReturnType<IdentityStore["verifySessionToken"]>>;
    }
  | { kind: "pat"; verified: VerifiedPat }
  | { kind: "share"; verified: VerifiedShare };

/**
 * Stores that {@link resolveBearer} dispatches to. The session store
 * is required (sessions are the only universally adopted form);
 * PAT and share verifiers are optional — omit them when the deployment
 * doesn't issue those token types.
 */
export interface ResolveBearerStores {
  /**
   * REQUIRED. Provides `verifySessionToken`. Any non-`pat_…` /
   * non-`shr_…` prefix routes here, since session tokens have no
   * spec-pinned prefix (adopters typically use opaque random strings).
   */
  identityStore: Pick<IdentityStore, "verifySessionToken" | "verifyPatToken">;
  /**
   * OPTIONAL. Provides `verifyShareToken`. When omitted, `shr_…`
   * tokens fail with `auth.token_format_unrecognized` instead of
   * being routed.
   */
  shareStore?: Pick<ShareStore, "verifyShareToken">;
}

/**
 * Pure prefix classifier. Returns the `auth.kind` discriminator value
 * for the candidate token without invoking any verifier or hitting
 * any store. The cross-SDK conformance contract — see
 * `spec/conformance/fixtures/identity/pat/bearer-prefix-routing.json`
 * — pins the classification rules every conforming SDK MUST produce
 * identically.
 *
 * Used by {@link resolveBearer} internally; exposed as a public helper
 * for adopters who need to populate `auth.kind` in audit records
 * before the verifier runs (e.g., logging the classification of a
 * token that subsequently fails verification).
 */
export function classifyBearer(token: string): "pat" | "share" | "session" {
  if (token.startsWith("pat_")) return "pat";
  if (token.startsWith("shr_")) return "share";
  return "session";
}

/**
 * Inspect the token prefix and dispatch to the matching verifier.
 *
 * Routing:
 *   - `pat_<32hex>_<…>` → `identityStore.verifyPatToken` (ADR 0016)
 *   - `shr_<…>`        → `shareStore.verifyShareToken` (ADR 0012)
 *   - everything else  → `identityStore.verifySessionToken` (v0.1)
 *
 * Errors thrown by the underlying verifier propagate unchanged
 * (`InvalidPatTokenError`, `PatExpiredError`, `PatRevokedError`,
 * `InvalidShareTokenError`, etc.). The middleware layer maps those to
 * HTTP responses.
 *
 * `TokenFormatUnrecognizedError` is thrown ONLY for prefixes that
 * exist in the spec but aren't wired in this deployment (e.g. a
 * `shr_…` token presented when no shareStore was supplied). Mis-typed
 * pasting and other malformed-bearer cases route to the session
 * verifier (which itself throws `InvalidTokenError`).
 */
export async function resolveBearer(
  token: string,
  stores: ResolveBearerStores,
): Promise<ResolvedBearer> {
  if (token.startsWith("pat_")) {
    const verified = await stores.identityStore.verifyPatToken(token);
    return { kind: "pat", verified };
  }
  if (token.startsWith("shr_")) {
    if (!stores.shareStore) {
      throw new TokenFormatUnrecognizedError(
        "share-token bearer presented but no shareStore is wired",
      );
    }
    const verified = await stores.shareStore.verifyShareToken(token);
    return { kind: "share", verified };
  }
  // Anything else — session resolver. Session tokens have no
  // spec-pinned prefix; adopters typically use opaque random strings.
  const session = await stores.identityStore.verifySessionToken(token);
  return { kind: "session", session };
}
