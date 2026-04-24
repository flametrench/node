// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/** Base for adapter-thrown errors. Re-throws of identity-layer errors retain their original types. */
export class FlametrenchNextError extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
    this.name = "FlametrenchNextError";
  }
}

/** Thrown by `requireSession()` when no valid session is present. */
export class UnauthenticatedError extends FlametrenchNextError {
  constructor() {
    super("No authenticated session", "unauthenticated");
    this.name = "UnauthenticatedError";
  }
}
