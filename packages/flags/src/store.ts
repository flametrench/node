// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type { CreateFlagInput, Flag, FlagId, OrgId, UpdateFlagInput } from "./types.js";

/**
 * The FlagStore interface is the contract every feature-flag backend fulfills.
 *
 * Targeting for `evaluate` uses two mechanisms (ADR 0021):
 *   - `authz` rules: delegated to the injected `check()` function.
 *   - `percentage` rules: deterministic bucketing via SHA-256 (ADR 0021 §Deterministic bucketing).
 *
 * Cross-scope non-disclosure: `get`/`update`/`delete` targeting a flag in a
 * foreign scope MUST raise the same `NotFoundError` — no presence differential.
 *
 * `evaluate` is the hot-path; it MUST NOT emit audit events.
 * `createFlag`/`updateFlag`/`deleteFlag` MUST emit `aud` events (wired by adopters).
 */
export interface FlagStore {
  createFlag(input: CreateFlagInput): Promise<Flag>;
  getFlag(id: FlagId): Promise<Flag>;
  getFlagByKey(scope: OrgId, key: string): Promise<Flag>;
  updateFlag(id: FlagId, input: UpdateFlagInput): Promise<Flag>;
  deleteFlag(id: FlagId): Promise<Flag>;
  evaluate(scope: OrgId, key: string, subjectId: string): Promise<boolean>;
}
