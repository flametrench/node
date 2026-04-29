// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// Block publishes from anything other than pnpm. Bare `npm publish` ships
// unresolved `workspace:*` deps and breaks adopters' installs — verified
// 2026-04-29 when both @flametrench/identity@0.2.0-rc.6 and
// @flametrench/tenancy@0.2.0-rc.4 had to be deprecated and republished.
// pnpm rewrites workspace specs to actual versions at publish time; npm
// does not.
//
// This script runs as a `prepublishOnly` lifecycle hook in every
// publishable package. Both `npm publish` and `pnpm publish` execute
// prepublishOnly, but they set different user-agents. We refuse to
// proceed unless the agent starts with `pnpm/`.

const ua = String(process.env.npm_config_user_agent || "");

if (!ua.startsWith("pnpm/")) {
  console.error("");
  console.error(
    "ERROR: This monorepo MUST publish via `pnpm publish`, not `npm publish`."
  );
  console.error(
    "Bare `npm publish` ships unresolved `workspace:*` deps and breaks"
  );
  console.error(
    "adopters' installs. See spec ADR 0013 commit and the rc.6/rc.7"
  );
  console.error("incident in spec/CHANGELOG for context.");
  console.error("");
  console.error(`user-agent observed: ${ua || "(empty)"}`);
  console.error("");
  console.error("To publish:");
  console.error("  cd packages/<pkg>");
  console.error("  pnpm publish --tag rc");
  console.error("");
  process.exit(1);
}
