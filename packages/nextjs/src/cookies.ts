// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Abstract cookie store interface compatible with Next 15's `cookies()`
 * return shape. We type only what we use so the adapter can be tested
 * with a fake implementation that doesn't import next/headers.
 */
export interface CookieStore {
  get(name: string): { name: string; value: string } | undefined;
  set(
    name: string,
    value: string,
    options?: {
      httpOnly?: boolean;
      secure?: boolean;
      sameSite?: "strict" | "lax" | "none";
      path?: string;
      maxAge?: number;
      domain?: string;
      expires?: Date;
    },
  ): void;
  delete(name: string): void;
}

/**
 * Resolver returning a CookieStore for the current request. In production
 * this is the result of `await cookies()` from `next/headers`. In tests
 * it's a fake.
 */
export type CookieAccessor = () => Promise<CookieStore> | CookieStore;
