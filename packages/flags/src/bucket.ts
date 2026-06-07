// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Deterministic percentage-rollout bucketing (ADR 0021 §Deterministic bucketing).
// Pinned for cross-SDK identity: bucket(key, subject_id) must be byte-identical
// across all SDK families.

import { createHash } from "node:crypto";

const NUL = Buffer.from([0x00]);

/**
 * Computes the rollout bucket for a (key, subject_id) pair.
 *
 * Algorithm: SHA-256( utf8(key) || 0x00 || utf8(subject_id) ), take the first
 * 4 bytes as a big-endian uint32, mod 10000 → basis points [0, 9999].
 *
 * subject_id MUST be the full wire-format id string (e.g. "usr_0190f2...") —
 * not the bare hex payload, not the hyphenated UUID, not decoded bytes.
 */
export function assignBucket(key: string, subjectId: string): number {
  const hash = createHash("sha256");
  hash.update(key, "utf8");
  hash.update(NUL);
  hash.update(subjectId, "utf8");
  const digest = hash.digest();
  const n = digest.readUInt32BE(0);
  return n % 10000;
}
