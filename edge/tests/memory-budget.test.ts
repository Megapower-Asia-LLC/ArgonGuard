import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";
import { UnsupportedEnvironmentError } from "@argonguard/core";
import { createWasmArgon2Provider, wasmPagesForM, WORKERS_MAX_WASM_PAGES } from "../src/engine/wasmArgon2Provider.js";

/**
 * 記憶體預算守衛（PPLX edge 審核 #1/#2）：highest（m=131072）在 Cloudflare Workers 128MB
 * isolate 會 memory.grow 超限被 OOM kill。純算術 + 引擎守衛測試——因 Miniflare 不強制 128MB，
 * 不能只靠 workerd.test.ts 抓；把記憶體預算變成建置期紅燈，避免未來新增 profile 回歸。
 */
const require = createRequire(import.meta.url);
const simd = (imp: WebAssembly.Imports) => WebAssembly.instantiate(readFileSync(require.resolve("argon2id/dist/simd.wasm")), imp);
const nonSimd = (imp: WebAssembly.Imports) => WebAssembly.instantiate(readFileSync(require.resolve("argon2id/dist/no-simd.wasm")), imp);
const S = new Uint8Array(Buffer.from("AronGuardV1S01!!"));
const P = new Uint8Array(Buffer.from("password"));

describe("記憶體預算守衛（highest 在 Workers 128MB OOM）", () => {
  it("WASM 頁數：default/high ≤ Workers 上限、highest 超限", () => {
    expect(wasmPagesForM(19456)).toBeLessThanOrEqual(WORKERS_MAX_WASM_PAGES); // default
    expect(wasmPagesForM(65536)).toBeLessThanOrEqual(WORKERS_MAX_WASM_PAGES); // high
    expect(wasmPagesForM(131072)).toBeGreaterThan(WORKERS_MAX_WASM_PAGES); // highest → OOM band
  });

  it("Workers 上限（預設 2048）下 highest 拋 UnsupportedEnvironmentError（非 isolate OOM）", async () => {
    const engine = createWasmArgon2Provider(simd, nonSimd);
    await expect(engine.hashRaw(P, S, 131072, 2, 1, 32)).rejects.toBeInstanceOf(UnsupportedEnvironmentError);
  });

  it("verify 路徑同守衛：Workers 上限下驗證他平台高 m 雜湊也拋 typed error（非崩潰）", async () => {
    const engine = createWasmArgon2Provider(simd, nonSimd);
    // hashRaw 是 verify recompute 的路徑；MAX_M=262144 直接拋，不讓 isolate 崩潰
    await expect(engine.hashRaw(P, S, 262144, 2, 1, 32)).rejects.toBeInstanceOf(UnsupportedEnvironmentError);
  });

  it("提高 maxWasmPages 可在高記憶體環境（瀏覽器/Vercel）啟用 highest", async () => {
    const engine = createWasmArgon2Provider(simd, nonSimd, 8192);
    const tag = await engine.hashRaw(P, S, 131072, 2, 1, 32);
    expect(tag.length).toBe(32);
  });
});
