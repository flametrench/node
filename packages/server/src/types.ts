// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type { TupleStore } from "@flametrench/authz";
import type { IdentityStore, Session } from "@flametrench/identity";
import type { TenancyStore } from "@flametrench/tenancy";

/** Configuration for `createFlametrenchServer`. */
export interface FlametrenchServerConfig {
  identityStore: IdentityStore;
  tenancyStore: TenancyStore;
  tupleStore: TupleStore;

  /**
   * Route prefix. Defaults to "/v1", matching the OpenAPI `servers`
   * declaration. Set to "" to mount at the root.
   */
  prefix?: string;

  /**
   * Called for every successful session verification. Lets applications
   * observe bearer auth (logging, metrics) without intercepting the
   * request pipeline.
   */
  onAuthenticated?: (session: Session) => void | Promise<void>;
}

/**
 * Augmentation of Fastify's request object with the verified session, set
 * by the bearer-auth middleware on authenticated routes.
 */
declare module "fastify" {
  interface FastifyRequest {
    flametrenchSession?: Session;
  }
}
