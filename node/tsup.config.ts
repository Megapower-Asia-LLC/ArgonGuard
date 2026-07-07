import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  // .d.ts 改由 tsc + api-extractor（bundledPackages）產生：api-extractor 能把 core 的
  // 型別 inline 進 rollup，tsup 的 dts/dts.resolve/experimentalDts 皆無法（實測）。見 build:dts。
  dts: false,
  // core 的 runtime 程式碼打包進 node dist（file: 依賴不 portable，發佈與 harness 皆需 dist 自包含）。
  // tsup CLI 不支援 --noExternal，必須用 config（edge 亦同）。
  noExternal: ["@argonguard/core"],
});
