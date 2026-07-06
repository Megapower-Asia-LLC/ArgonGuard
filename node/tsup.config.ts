import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  // core 打包進 node dist（file: 依賴不 portable，發佈與 harness 皆需 dist 自包含）。
  // tsup CLI 不支援 --noExternal，必須用 config（edge 亦同）。
  noExternal: ["@argonguard/core"],
});
