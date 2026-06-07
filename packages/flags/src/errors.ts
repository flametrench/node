// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

export class FlagError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = this.constructor.name;
  }
}

export class InvalidFormatError extends FlagError {
  constructor(
    readonly field: string,
    message: string,
  ) {
    super("INVALID_FORMAT", message);
  }
}

export class NotFoundError extends FlagError {
  constructor(message: string) {
    super("NOT_FOUND", message);
  }
}

export class PreconditionError extends FlagError {
  constructor(message: string) {
    super("PRECONDITION", message);
  }
}
