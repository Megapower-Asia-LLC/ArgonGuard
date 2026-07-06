import setupWasm, { type computeHash } from "argon2id/lib/setup.js";
import { ReasonCodes, UnsupportedEnvironmentError, type Argon2Provider } from "@argonguard/core";

/** WASM 實例載入器（平台特定）：workerd 傳靜態 import 的 Module，Node 傳 fs.readFileSync 的 bytes。 */
export type WasmInstanceLoader = (
  importObject: WebAssembly.Imports,
) => WebAssembly.WebAssemblyInstantiatedSource | Promise<WebAssembly.WebAssemblyInstantiatedSource>;

const WASM_PAGE_BYTES = 65536;
const ARGON2ID_OVERHEAD_BYTES = 10 * 1024; // argon2id.js: requiredMemory = m*1024 + 10 KiB

/**
 * Cloudflare Workers 每 isolate 記憶體上限 128 MiB = 2048 頁。argon2id 對 m KiB 需
 * ceil((m*1024 + 10KiB)/64KiB) 頁：default(m=19456)=305 頁、high(m=65536)=1025 頁 皆 ≤2048；
 * highest(m=131072)=2049 頁 > 2048 → 在 Workers 會 memory.grow 失敗、isolate 被 OOM kill。
 * 預設以此為上限，讓超限「明確拋 typed error」而非不透明崩潰。瀏覽器 / Vercel Edge 等
 * 高記憶體環境可經 maxWasmPages 調高以啟用 highest。
 */
export const WORKERS_MAX_WASM_PAGES = 2048;

/** m（KiB）在 argon2id WASM 需要的線性記憶體頁數。 */
export function wasmPagesForM(m: number): number {
  return Math.ceil((m * 1024 + ARGON2ID_OVERHEAD_BYTES) / WASM_PAGE_BYTES);
}

/**
 * 以 argon2id（純 WASM）引擎建立 core Argon2Provider。
 *
 * lazy singleton：wasm 只 setup 一次（PPLX 致命 #1）。參數對照 core hashRaw：
 * m→memorySize(KiB)、t→passes、p→parallelism、tagLength→tagLength。
 *
 * maxWasmPages 記憶體守衛（PPLX edge 審核 #1/#2）：hashRaw 是 hash 與 verify 的共同路徑，
 * 於進入引擎前預檢 m 對應頁數，超過上限即拋 UnsupportedEnvironmentError——涵蓋
 * 「以 highest 產生雜湊」與「在 Workers 驗證他平台以 highest/高 m 產生的雜湊」兩路徑，
 * 把不透明的 isolate OOM 換成可攔截的 typed error，維持跨引擎一致性的可預期失敗。
 */
export function createWasmArgon2Provider(
  getSIMD: WasmInstanceLoader,
  getNonSIMD: WasmInstanceLoader,
  maxWasmPages: number = WORKERS_MAX_WASM_PAGES,
): Argon2Provider {
  let ready: Promise<computeHash> | null = null;
  const load = (): Promise<computeHash> => (ready ??= setupWasm(getSIMD, getNonSIMD));
  return {
    async hashRaw(password, salt, m, t, p, tagLength): Promise<Uint8Array> {
      if (wasmPagesForM(m) > maxWasmPages) {
        throw new UnsupportedEnvironmentError(ReasonCodes.Argon2idUnavailable);
      }
      const argon2id = await load();
      return argon2id({ password, salt, parallelism: p, passes: t, memorySize: m, tagLength });
    },
  };
}
