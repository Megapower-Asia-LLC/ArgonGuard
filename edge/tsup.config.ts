import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  // core 打包進 edge dist（file: 依賴不 portable，發佈自包含）
  noExternal: ["@argonguard/core"],
  // argon2id（含 dist/*.wasm 靜態 import）保持 external，由消費者的 wrangler
  // 以 [[rules]] type="CompiledWasm" 處理靜態 wasm import
  external: ["argon2id"],
});
