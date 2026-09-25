import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // Postgres integration tests share a database; run files serially.
    fileParallelism: false,
  },
});
