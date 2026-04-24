// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Thrown when an ID string is malformed or cannot be parsed as a
 * Flametrench wire-format identifier.
 */
export class InvalidIdError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidIdError";
  }
}

/**
 * Thrown when an ID uses a type prefix that is not in the registered
 * type prefix set.
 */
export class InvalidTypeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidTypeError";
  }
}
