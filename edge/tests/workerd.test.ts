import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { unstable_dev, type Unstable_DevWorker } from "wrangler";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/**
 * 真 workerd（Miniflare）驗證：確認 edge 套件的 wasm 靜態 import（wrangler CompiledWasm →
 * WebAssembly.Module）與 WebAssembly.instantiate 在 workerd runtime 實際可跑，且與四語言
 * 凍結向量 bit-identical。vitest 的 esbuild transpile 不代表 workerd 行為，故此測試必要（PPLX）。
 */
const VECTORS = join(dirname(fileURLToPath(import.meta.url)), "../../spec/vectors/v1");
const load = (name: string) => JSON.parse(readFileSync(join(VECTORS, name), "utf8")).entries as any[];
const utf8 = (hex: string) => Buffer.from(hex, "hex").toString("utf8");

let worker: Unstable_DevWorker;
const post = async (body: unknown) =>
  (await worker.fetch("http://x/", { method: "POST", body: JSON.stringify(body) })).json() as any;

beforeAll(async () => {
  worker = await unstable_dev(join(dirname(fileURLToPath(import.meta.url)), "../test-worker/index.ts"), {
    config: join(dirname(fileURLToPath(import.meta.url)), "../wrangler.jsonc"),
    experimental: { disableExperimentalWarning: true },
  });
}, 60_000);
afterAll(async () => { if (worker) await worker.stop(); });

describe("workerd runtime（Miniflare）", () => {
  it("hash → verify round-trip in workerd", async () => {
    const { encoded } = await post({ op: "hash", password: "correct horse battery staple" });
    expect(encoded).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    const { ok } = await post({ op: "verify", password: "correct horse battery staple", encoded });
    expect(ok).toBe(true);
  });

  it("workerd(argon2id) 驗證四語言凍結向量（正+負 → 只 accept 該 accept 的，抓驗證繞過）", async () => {
    // 不 filter：4 個負向量（wrong-password / tampered-salt / tampered-tag / nfc-vs-nfd）
    // 必須在真 workerd 跑，false-accept（驗證繞過）才會讓此 job 轉紅（PPLX 審核 #4）
    for (const e of load("verify.json")) {
      const { ok } = await post({ op: "verify", password: utf8(e.passwordHex), encoded: e.encoded });
      expect(ok, e.id).toBe(e.expected);
    }
  });

  it("workerd 產出的 hash 與 deterministic 凍結向量同參數（跨引擎驗證）", async () => {
    // workerd 用隨機 salt，故驗證「workerd 產出能被自己 verify」+ 參數段正確
    const { encoded } = await post({ op: "hash", password: "password", profile: "high" });
    expect(encoded).toMatch(/^\$argon2id\$v=19\$m=65536,t=2,p=1\$/);
    const { ok } = await post({ op: "verify", password: "password", encoded });
    expect(ok).toBe(true);
  });
});
