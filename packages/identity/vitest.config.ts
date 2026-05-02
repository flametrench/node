import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // Argon2id verification at spec-floor parameters takes ~50-150ms per hash;
    // tests that create multiple credentials need longer than the default.
    testTimeout: 15000,
    // Postgres integration test files all DROP SCHEMA / load schema in
    // beforeEach against the same database — running files in parallel
    // races on schema state. The PAT tests added in v0.3 made this race
    // visible; serializing files keeps the suite deterministic.
    fileParallelism: false,
  },
});
