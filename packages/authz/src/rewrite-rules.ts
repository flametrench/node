// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Authorization rewrite rules — v0.2 reference per ADR 0007.
 *
 * The v0.1 SDK exposed only direct-tuple matching. v0.2 adds a deliberate
 * subset of Zanzibar userset_rewrite, so applications can declare role
 * implication ("admin implies editor") and parent-child inheritance ("org
 * viewer implies project viewer for org-owned projects") without
 * denormalizing tuples into the store.
 *
 * Three rule node types:
 *
 *   - `This` — the explicit-tuple set; equivalent to v0.1 `check()` semantics.
 *   - `ComputedUserset` — role implication on the same object.
 *   - `TupleToUserset` — parent-child inheritance via a relation hop.
 *
 * In v0.2, `This` is always implicitly part of every rule's union — the
 * direct-tuple fast path runs before rule expansion. Listing it explicitly
 * in a rule is documentation, not behavior.
 */

import { EvaluationLimitExceededError } from "./errors.js";

export interface ThisNode {
  type: "this";
}

export interface ComputedUserset {
  type: "computed_userset";
  /** The relation to recurse with on the same object. */
  relation: string;
}

export interface TupleToUserset {
  type: "tuple_to_userset";
  /** Relation traversed on the current object to find the next hop. */
  tuplesetRelation: string;
  /** Relation to check on the subject reached via the tupleset hop. */
  computedUsersetRelation: string;
}

export type RuleNode = ThisNode | ComputedUserset | TupleToUserset;

/** A rule body is a union of one or more nodes. */
export type Rule = readonly RuleNode[];

/** Rules keyed on (objectType, relation). */
export type Rules = {
  readonly [objectType: string]: {
    readonly [relation: string]: Rule;
  };
};

// ─── Evaluation limits ───
//
// Spec floor depth and fan-out per ADR 0007. Configurable per-store via
// the InMemoryTupleStore constructor options.

export const DEFAULT_MAX_DEPTH = 8;
export const DEFAULT_MAX_FAN_OUT = 1024;

// ─── Evaluation ───

interface Frame {
  readonly relation: string;
  readonly objectType: string;
  readonly objectId: string;
}

export interface EvaluationResult {
  allowed: boolean;
  matchedTupleId: string | null;
}

/**
 * Returns the matched direct tuple id or null.
 *
 * v0.3 (ADR 0017): async-capable. InMemoryTupleStore wraps a sync map
 * probe in `Promise.resolve(...)`; PostgresTupleStore issues a real
 * SELECT.
 */
export type DirectLookup = (
  subjectType: string,
  subjectId: string,
  relation: string,
  objectType: string,
  objectId: string,
) => Promise<string | null>;

/**
 * Returns the {subjectType, subjectId, tupId} list for the
 * (object, relation) pair. Async per ADR 0017.
 */
export type ListByObject = (
  objectType: string,
  objectId: string,
  relation: string | null,
) => Promise<{ subjectType: string; subjectId: string; tupId: string }[]>;

export interface EvaluateOptions {
  rules: Rules | null;
  subjectType: string;
  subjectId: string;
  relation: string;
  objectType: string;
  objectId: string;
  directLookup: DirectLookup;
  listByObject: ListByObject;
  maxDepth?: number;
  maxFanOut?: number;
}

/**
 * Evaluate `check()` with optional rewrite-rule expansion.
 *
 * Layered exactly as ADR 0007 prescribes:
 *
 *   1. Direct lookup. If a tuple matches, return it. v0.1 fast path.
 *   2. Rule expansion. If a rule exists for `(objectType, relation)`,
 *      expand its primitives. Each primitive recurses with bounded depth
 *      and tracks a frame stack for cycle detection.
 *   3. Short-circuit on first match. Union semantics: any sub-evaluation
 *      returning `allowed` ends the evaluation.
 *
 * Cycle detection: per-evaluation, the stack of `(relation, objectType,
 * objectId)` frames is checked before each recursive call. A repeat
 * frame returns `denied` for that branch (the cycle adds no information)
 * without raising.
 *
 * Bounds: `maxDepth` is the recursion ceiling. `maxFanOut` is the
 * per-`TupleToUserset` enumeration ceiling. Either exceeded raises
 * `EvaluationLimitExceededError`.
 *
 * v0.3 (ADR 0017): async-capable. Sequential expansion preserves
 * cycle-detection stack semantics across awaits — DO NOT parallelize
 * sub-branches without re-deriving the stack guarantees.
 */
export async function evaluate(opts: EvaluateOptions): Promise<EvaluationResult> {
  const {
    rules,
    subjectType,
    subjectId,
    directLookup,
    listByObject,
    maxDepth = DEFAULT_MAX_DEPTH,
    maxFanOut = DEFAULT_MAX_FAN_OUT,
  } = opts;

  const go = async (
    relation: string,
    objectType: string,
    objectId: string,
    stack: readonly Frame[],
    depth: number,
  ): Promise<EvaluationResult> => {
    // 1. Direct lookup.
    const direct = await directLookup(
      subjectType,
      subjectId,
      relation,
      objectType,
      objectId,
    );
    if (direct !== null) {
      return { allowed: true, matchedTupleId: direct };
    }

    // 2. Rule expansion.
    if (rules === null) {
      return { allowed: false, matchedTupleId: null };
    }
    const rule = rules[objectType]?.[relation];
    if (rule === undefined) {
      return { allowed: false, matchedTupleId: null };
    }

    // Cycle detection.
    const frame: Frame = { relation, objectType, objectId };
    if (
      stack.some(
        (f) =>
          f.relation === frame.relation &&
          f.objectType === frame.objectType &&
          f.objectId === frame.objectId,
      )
    ) {
      return { allowed: false, matchedTupleId: null };
    }

    // Depth bound.
    if (depth >= maxDepth) {
      throw new EvaluationLimitExceededError(
        `Rule evaluation exceeded depth limit (${maxDepth}) at ${objectType}.${relation} for ${objectType}_${objectId}`,
      );
    }

    const newStack = [...stack, frame];

    for (const node of rule) {
      if (node.type === "this") {
        // Already covered by step 1.
        continue;
      }
      if (node.type === "computed_userset") {
        const result = await go(
          node.relation,
          objectType,
          objectId,
          newStack,
          depth + 1,
        );
        if (result.allowed) return result;
        continue;
      }
      if (node.type === "tuple_to_userset") {
        const related = await listByObject(objectType, objectId, node.tuplesetRelation);
        if (related.length > maxFanOut) {
          throw new EvaluationLimitExceededError(
            `tuple_to_userset fan-out exceeded (${related.length} > ${maxFanOut}) at ${objectType}.${relation} via ${node.tuplesetRelation}`,
          );
        }
        for (const { subjectType: relSubType, subjectId: relSubId } of related) {
          const result = await go(
            node.computedUsersetRelation,
            relSubType,
            relSubId,
            newStack,
            depth + 1,
          );
          if (result.allowed) return result;
        }
        continue;
      }
      // TypeScript exhaustiveness check.
      const _exhaustive: never = node;
      void _exhaustive;
    }

    return { allowed: false, matchedTupleId: null };
  };

  return go(opts.relation, opts.objectType, opts.objectId, [], 0);
}

// EvaluationLimitExceededError lives in errors.ts to keep the error
// hierarchy consolidated. Re-export here for convenience.
export { EvaluationLimitExceededError } from "./errors.js";
