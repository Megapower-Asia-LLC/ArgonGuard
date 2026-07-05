import { Algorithm, hash as nativeHash, Version } from "@node-rs/argon2";
import { describe, expect, it } from "vitest";
import { hashPasswordWithSaltForConformance } from "../src/internal/conformance.js";
import { hex, vectorEntries } from "./vectors.js";

/**
 * 交叉比對（CI 防呆）：固定 salt 下，自寫 PHC encoder（hashRaw + encodePhc）輸出
 * 必須與 @node-rs/argon2 原生 hash()（帶 salt option）的 PHC 字串完全一致。
 * 防止自寫 encoder 與引擎原生序列化出現任何漂移。
 */
describe("自寫 PHC encoder vs @node-rs/argon2 原生 hash()", () => {
  for (const e of vectorEntries("deterministic.json")) {
    it(`${e.id}: byte-identical`, async () => {
      const ours = await hashPasswordWithSaltForConformance(
        hex(e.passwordHex),
        hex(e.saltHex),
        e.m,
        e.t,
        e.p,
        e.tagLen,
      );
      const native = await nativeHash(hex(e.passwordHex), {
        salt: hex(e.saltHex),
        memoryCost: e.m,
        timeCost: e.t,
        parallelism: e.p,
        outputLen: e.tagLen,
        algorithm: Algorithm.Argon2id,
        version: Version.V0x13,
      });
      expect(ours).toBe(native);
      expect(ours).toBe(e.encoded);
    });
  }
});
