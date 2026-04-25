// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { v7 as uuidv7, validate as uuidValidate } from "uuid";
import { InvalidIdError, InvalidTypeError } from "./errors.js";

export { InvalidIdError, InvalidTypeError };

/**
 * Registered type prefixes for Flametrench v0.1.
 *
 * Keep this map synchronized with the Flametrench specification's
 * reserved prefix registry at:
 * https://github.com/flametrench/spec/blob/main/docs/ids.md
 *
 * Parallel implementations (Laravel, future SDKs) must use the same
 * prefixes and semantics.
 */
export const TYPES = {
  usr: "user",
  org: "organization",
  mem: "membership",
  inv: "invitation",
  ses: "session",
  cred: "credential",
  tup: "authorization_tuple",
} as const satisfies Record<string, string>;

export type IdType = keyof typeof TYPES;

/**
 * The shape returned by {@link decode}.
 */
export interface DecodedId {
  type: IdType;
  uuid: string;
}

const HEX_PAYLOAD_LENGTH = 32;
const HEX_PATTERN = /^[0-9a-f]{32}$/;
const VERSION_NIBBLE_PATTERN = /^[1-8]$/;

/**
 * Encode a type and UUID into Flametrench wire format.
 *
 * @example
 * encode("usr", "0190f2a8-1b3c-7abc-8123-456789abcdef")
 * // → "usr_0190f2a81b3c7abc8123456789abcdef"
 *
 * @throws {InvalidTypeError} If the type prefix is not registered.
 * @throws {InvalidIdError} If the UUID is not a valid UUID.
 */
export function encode(type: string, uuid: string): string {
  assertType(type);

  if (!uuidValidate(uuid)) {
    throw new InvalidIdError(`Value is not a valid UUID: ${uuid}`);
  }

  const hex = uuid.replaceAll("-", "").toLowerCase();
  return `${type}_${hex}`;
}

/**
 * Decode a Flametrench wire-format ID into its type and canonical UUID.
 *
 * @example
 * decode("usr_0190f2a81b3c7abc8123456789abcdef")
 * // → { type: "usr", uuid: "0190f2a8-1b3c-7abc-8123-456789abcdef" }
 *
 * @throws {InvalidIdError} If the ID is malformed.
 * @throws {InvalidTypeError} If the type prefix is not registered.
 */
export function decode(id: string): DecodedId {
  const separator = id.indexOf("_");
  if (separator === -1) {
    throw new InvalidIdError(`ID missing type separator: ${id}`);
  }

  const type = id.slice(0, separator);
  const hex = id.slice(separator + 1);

  assertType(type);

  if (hex.length !== HEX_PAYLOAD_LENGTH || !HEX_PATTERN.test(hex)) {
    throw new InvalidIdError(
      `ID payload is not 32 lowercase hex characters: ${id}`,
    );
  }

  // Version nibble (13th hex char) must be 1-8. This rejects the Nil UUID
  // (v0) and Max UUID (v15/f), which the `uuid` package's validate() accepts
  // but are not meaningful identifiers.
  if (!VERSION_NIBBLE_PATTERN.test(hex[12]!)) {
    throw new InvalidIdError(`ID payload is not a valid UUID: ${id}`);
  }

  const canonical = [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-");

  return { type, uuid: canonical };
}

/**
 * Decode a Flametrench wire-format ID without checking the registered-type set.
 *
 * Use this for backend storage adapters that need to convert wire-format
 * object IDs to canonical UUIDs without knowing the application's
 * domain types in advance — e.g., when an authz tuple has
 * `objectType: "proj"` and `objectId: "proj_0190f2a8..."`.
 *
 * Validates wire-format shape (separator, 32-char lowercase hex, version
 * nibble 1–8). Does NOT consult `TYPES`. See spec/docs/ids.md.
 *
 * @throws {InvalidIdError} If the ID's structure is malformed. Never
 *                          throws `InvalidTypeError`.
 */
export function decodeAny(id: string): { type: string; uuid: string } {
  const separator = id.indexOf("_");
  if (separator === -1) {
    throw new InvalidIdError(`ID missing type separator: ${id}`);
  }

  const type = id.slice(0, separator);
  const hex = id.slice(separator + 1);

  if (type.length === 0) {
    throw new InvalidIdError(`ID has empty type prefix: ${id}`);
  }

  if (hex.length !== HEX_PAYLOAD_LENGTH || !HEX_PATTERN.test(hex)) {
    throw new InvalidIdError(
      `ID payload is not 32 lowercase hex characters: ${id}`,
    );
  }

  if (!VERSION_NIBBLE_PATTERN.test(hex[12]!)) {
    throw new InvalidIdError(`ID payload is not a valid UUID: ${id}`);
  }

  const canonical = [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-");

  return { type, uuid: canonical };
}

/**
 * Check whether a string is a valid Flametrench wire-format ID.
 *
 * Optionally asserts that the ID is of a specific type.
 *
 * @example
 * isValid("usr_0190f2a81b3c7abc8123456789abcdef")           // true
 * isValid("usr_0190f2a81b3c7abc8123456789abcdef", "org")    // false
 */
export function isValid(id: string, expectedType?: IdType): boolean {
  try {
    const decoded = decode(id);
    if (expectedType !== undefined && decoded.type !== expectedType) {
      return false;
    }
    return true;
  } catch (error) {
    if (error instanceof InvalidIdError || error instanceof InvalidTypeError) {
      return false;
    }
    throw error;
  }
}

/**
 * Extract the type prefix from a wire-format ID.
 *
 * @throws {InvalidIdError} If the ID is malformed.
 * @throws {InvalidTypeError} If the type prefix is not registered.
 */
export function typeOf(id: string): IdType {
  return decode(id).type;
}

/**
 * Generate a fresh wire-format ID of the given type.
 *
 * Uses UUIDv7 so generated IDs are sortable by creation time.
 *
 * @example
 * generate("usr")
 * // → "usr_0190f2a81b3c7abc8123456789abcdef"
 *
 * @throws {InvalidTypeError} If the type prefix is not registered.
 */
export function generate(type: IdType): string {
  assertType(type);
  return encode(type, uuidv7());
}

/**
 * Type guard narrowing `unknown` to a valid Flametrench ID string.
 *
 * Useful at API boundaries where incoming values need validation.
 */
export function isId(value: unknown, expectedType?: IdType): value is string {
  return typeof value === "string" && isValid(value, expectedType);
}

/**
 * Predicate counterpart to {@link decodeAny}. Returns true for any
 * well-formed wire-format ID regardless of registry membership.
 *
 * Use this when validating input from external systems that may
 * legitimately reference application-defined object types.
 */
export function isValidShape(id: string): boolean {
  try {
    decodeAny(id);
    return true;
  } catch (error) {
    if (error instanceof InvalidIdError) {
      return false;
    }
    throw error;
  }
}

function assertType(type: string): asserts type is IdType {
  if (!Object.hasOwn(TYPES, type)) {
    const registered = Object.keys(TYPES).join(", ");
    throw new InvalidTypeError(
      `Unregistered type prefix: '${type}'. Registered prefixes: ${registered}.`,
    );
  }
}
