// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import argon2 from "argon2";

import { ARGON2ID_FLOOR } from "./types.js";

/**
 * Verify a candidate plaintext password against a PHC-encoded Argon2id hash.
 *
 * This is the low-level cross-SDK parity primitive: every conforming
 * Flametrench identity SDK MUST verify the same PHC hash to the same
 * plaintext, regardless of the language (Node, PHP, Python, Java) or
 * Argon2 binding used. The conformance suite's `identity/argon2id.json`
 * fixture exercises this guarantee directly.
 *
 * Returns false on any verification failure (wrong password, malformed
 * hash, unsupported algorithm). Never throws on bad input — the contract
 * is "did this plaintext produce that hash?", and the answer to a malformed
 * hash is "no".
 */
export async function verifyPasswordHash(
  phcHash: string,
  candidatePassword: string,
): Promise<boolean> {
  try {
    return await argon2.verify(phcHash, candidatePassword);
  } catch {
    return false;
  }
}

/**
 * Hash a plaintext password with Argon2id at or above the spec floor
 * (`ARGON2ID_FLOOR`). The returned string is PHC-encoded and verifies
 * against `verifyPasswordHash` on any conforming SDK.
 */
export async function hashPassword(plaintext: string): Promise<string> {
  return argon2.hash(plaintext, {
    type: argon2.argon2id,
    memoryCost: ARGON2ID_FLOOR.memoryCost,
    timeCost: ARGON2ID_FLOOR.timeCost,
    parallelism: ARGON2ID_FLOOR.parallelism,
  });
}
