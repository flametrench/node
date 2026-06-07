// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

export class AuditError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = this.constructor.name;
  }
}

export class NotFoundError extends AuditError {
  constructor(message: string) {
    super("NOT_FOUND", message);
  }
}
