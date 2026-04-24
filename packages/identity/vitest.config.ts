import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // Argon2id verification at spec-floor parameters takes ~50-150ms per hash;
    // tests that create multiple credentials need longer than the default.
    testTimeout: 15000,
  },
});
