import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/postgres.ts"],
  format: ["esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  target: "node20",
  // `pg` is a peer dep — never bundle it.
  external: ["pg"],
});
