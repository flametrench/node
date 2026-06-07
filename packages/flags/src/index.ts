// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * @flametrench/flags — feature-flag primitive with authz-based targeting and
 * deterministic percentage rollouts.
 *
 * Exports:
 *   - Entity types matching the wire contract.
 *   - A FlagStore interface — the contract every backend fulfills.
 *   - An InMemoryFlagStore implementation — reference / tests.
 *   - assignBucket — the cross-SDK-pinned rollout bucket function.
 *   - Error classes with spec-stable `code` identifiers.
 */

export type {
  AuthzRule,
  CreateFlagInput,
  Flag,
  FlagId,
  OrgId,
  PercentageRule,
  Rule,
  UpdateFlagInput,
  UsrId,
} from "./types.js";

export type { FlagStore } from "./store.js";

export { assignBucket } from "./bucket.js";

export { InMemoryFlagStore } from "./in-memory.js";

export { FlagError, InvalidFormatError, NotFoundError, PreconditionError } from "./errors.js";
