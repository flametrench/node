// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { generate, isValid } from "@flametrench/ids";

import { assignBucket } from "./bucket.js";
import { InvalidFormatError, NotFoundError, PreconditionError } from "./errors.js";
import type { FlagStore } from "./store.js";
import type { AuthzRule, CreateFlagInput, Flag, FlagId, OrgId, PercentageRule, Rule, UpdateFlagInput } from "./types.js";

const KEY_PATTERN = /^[a-z0-9._-]{1,128}$/;
const RELATION_PATTERN = /^[a-z_]{2,32}$/;

function validateRules(rules: Rule[]): void {
  for (const rule of rules) {
    if (rule.kind === "authz") {
      const r = rule as AuthzRule;
      if (!RELATION_PATTERN.test(r.relation)) {
        throw new InvalidFormatError("rules", `authz rule relation must match ^[a-z_]{2,32}$, got: ${JSON.stringify(r.relation)}`);
      }
      if (!r.object || typeof r.object.type !== "string" || r.object.type.length === 0 || typeof r.object.id !== "string" || r.object.id.length === 0) {
        throw new InvalidFormatError("rules", `authz rule object must have non-empty type and id`);
      }
    } else if (rule.kind === "percentage") {
      const r = rule as PercentageRule;
      if (!Number.isInteger(r.basis_points) || r.basis_points < 0 || r.basis_points > 10000) {
        throw new InvalidFormatError("rules", `percentage rule basis_points must be an integer in [0, 10000], got: ${r.basis_points}`);
      }
    } else {
      throw new InvalidFormatError("rules", `unknown rule kind: ${JSON.stringify((rule as Rule).kind)}`);
    }
  }
}

function validateCreate(input: CreateFlagInput): void {
  if (!isValid(input.scope, "org")) {
    throw new InvalidFormatError("scope", `scope must be a valid org_<32hex>, got: ${String(input.scope)}`);
  }
  if (!KEY_PATTERN.test(input.key)) {
    throw new InvalidFormatError("key", `key must match ^[a-z0-9._-]{1,128}$, got: ${JSON.stringify(input.key)}`);
  }
  if (typeof input.enabled !== "boolean") {
    throw new InvalidFormatError("enabled", `enabled must be a boolean`);
  }
  if (typeof input.default_variant !== "boolean") {
    throw new InvalidFormatError("default_variant", `default_variant must be a boolean`);
  }
  if (!Array.isArray(input.rules)) {
    throw new InvalidFormatError("rules", `rules must be an array`);
  }
  validateRules(input.rules);
}

/**
 * Reference in-memory implementation of FlagStore (ADR 0021).
 *
 * Authz-based targeting is delegated to the injected `check` function. The
 * default (no check provided) treats every authz rule as non-matching —
 * percentage rules still work without an authz backend.
 *
 * Suitable for tests and in-memory prototyping. Not durable.
 */
export class InMemoryFlagStore implements FlagStore {
  private readonly flags = new Map<FlagId, Flag>();
  private readonly keyIndex = new Map<string, FlagId>();

  constructor(
    private readonly check: (subjectId: string, relation: string, objectType: string, objectId: string) => Promise<boolean> = async () => false,
  ) {}

  async createFlag(input: CreateFlagInput): Promise<Flag> {
    validateCreate(input);
    const indexKey = `${input.scope}::${input.key}`;
    if (this.keyIndex.has(indexKey)) {
      throw new PreconditionError(`Flag key '${input.key}' already exists in scope ${input.scope}`);
    }
    const id = generate("flag") as FlagId;
    const now = new Date();
    const flag: Flag = {
      id,
      scope: input.scope,
      key: input.key,
      enabled: input.enabled,
      default_variant: input.default_variant,
      rules: input.rules.map((r) => ({ ...r })),
      createdAt: now,
      updatedAt: now,
    };
    this.flags.set(id, flag);
    this.keyIndex.set(indexKey, id);
    return flag;
  }

  async getFlag(id: FlagId): Promise<Flag> {
    return this.getOrThrow(id);
  }

  async getFlagByKey(scope: OrgId, key: string): Promise<Flag> {
    const indexKey = `${scope}::${key}`;
    const id = this.keyIndex.get(indexKey);
    if (!id) throw new NotFoundError(`Flag not found: (scope=${scope}, key=${key})`);
    return this.getOrThrow(id);
  }

  async updateFlag(id: FlagId, input: UpdateFlagInput): Promise<Flag> {
    const f = this.getOrThrow(id);
    if (input.rules !== undefined) validateRules(input.rules);
    const updated: Flag = {
      ...f,
      enabled: input.enabled !== undefined ? input.enabled : f.enabled,
      default_variant: input.default_variant !== undefined ? input.default_variant : f.default_variant,
      rules: input.rules !== undefined ? input.rules.map((r) => ({ ...r })) : f.rules,
      updatedAt: new Date(),
    };
    this.flags.set(id, updated);
    return updated;
  }

  async deleteFlag(id: FlagId): Promise<Flag> {
    const f = this.getOrThrow(id);
    this.flags.delete(id);
    this.keyIndex.delete(`${f.scope}::${f.key}`);
    return f;
  }

  async evaluate(scope: OrgId, key: string, subjectId: string): Promise<boolean> {
    const indexKey = `${scope}::${key}`;
    const id = this.keyIndex.get(indexKey);
    if (!id) return false;
    const flag = this.flags.get(id)!;

    if (!flag.enabled) return flag.default_variant;

    for (const rule of flag.rules) {
      if (rule.kind === "authz") {
        const matches = await this.check(subjectId, rule.relation, rule.object.type, rule.object.id);
        if (matches) return rule.variant;
      } else {
        const bucket = assignBucket(key, subjectId);
        if (bucket < rule.basis_points) return rule.variant;
      }
    }

    return flag.default_variant;
  }

  private getOrThrow(id: FlagId): Flag {
    const f = this.flags.get(id);
    if (!f) throw new NotFoundError(`Flag not found: ${id}`);
    return f;
  }
}
