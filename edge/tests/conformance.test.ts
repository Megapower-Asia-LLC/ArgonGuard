import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ArgonGuardCoreHasher,
  ArgonGuardError,
  MalformedHashError,
  PolicyViolationError,
  UnsupportedAlgorithmError,
  webCryptoPrimitives,
  type ArgonGuardProfile,
  type CryptoPrimitives,
  type LegacyPasswordVerifier,
} from "@argonguard/core";
import { createWasmArgon2Provider } from "../src/engine/wasmArgon2Provider.js";

// 凍結向量（與四語言共用）
const VECTORS = join(dirname(fileURLToPath(import.meta.url)), "../../spec/vectors/v1");
const load = (name: string) => JSON.parse(readFileSync(join(VECTORS, name), "utf8")).entries as any[];
const bytes = (hex: string) => new Uint8Array(Buffer.from(hex, "hex"));
const utf8 = (hex: string) => Buffer.from(hex, "hex").toString("utf8");

// edge 引擎：argon2id 純 WASM（Node 測試用 fs loader；workerd 生產用靜態 import Module）
const require = createRequire(import.meta.url);
const engine = createWasmArgon2Provider(
  imp => WebAssembly.instantiate(readFileSync(require.resolve("argon2id/dist/simd.wasm")), imp),
  imp => WebAssembly.instantiate(readFileSync(require.resolve("argon2id/dist/no-simd.wasm")), imp),
);
const fixedSalt = (salt: Uint8Array): CryptoPrimitives => ({ randomBytes: () => salt, timingSafeEqual: webCryptoPrimitives.timingSafeEqual });
const bcryptClaimer: LegacyPasswordVerifier = { canHandle: e => e.startsWith("$2b$"), verify: () => false };

describe("edge deterministic 向量（argon2id WASM 與四語言 bit-identical）", () => {
  for (const e of load("deterministic.json")) {
    it(e.id, async () => {
      const hasher = new ArgonGuardCoreHasher({ engine, crypto: fixedSalt(bytes(e.saltHex)), profile: e.profile as ArgonGuardProfile });
      expect(await hasher.hashPassword(utf8(e.passwordHex))).toBe(e.encoded);
    });
  }
});

describe("edge verify 向量", () => {
  const hasher = new ArgonGuardCoreHasher({ engine, crypto: webCryptoPrimitives });
  for (const e of load("verify.json")) {
    it(e.id, async () => {
      expect(await hasher.verifyPassword(utf8(e.passwordHex), e.encoded)).toBe(e.expected);
    });
  }
});

describe("edge reject 向量（typed error + reason）", () => {
  const hasher = new ArgonGuardCoreHasher({ engine, crypto: webCryptoPrimitives });
  const errorClass: Record<string, unknown> = {
    MalformedHash: MalformedHashError, PolicyViolation: PolicyViolationError, UnsupportedAlgorithm: UnsupportedAlgorithmError,
  };
  for (const e of load("reject.json")) {
    it(e.id, async () => {
      try {
        await hasher.verifyPassword(utf8(e.passwordHex), e.encoded);
        throw new Error("expected throw");
      } catch (err) {
        expect(err).toBeInstanceOf(ArgonGuardError);
        expect((err as ArgonGuardError).reason).toBe(e.expectedReason);
        if (errorClass[e.expectedError]) expect(err).toBeInstanceOf(errorClass[e.expectedError] as never);
      }
    });
  }
});

describe("edge needs-rehash 向量", () => {
  for (const e of load("needs-rehash.json")) {
    it(e.id, () => {
      const hasher = new ArgonGuardCoreHasher({
        engine, crypto: webCryptoPrimitives,
        profile: e.activeProfile as ArgonGuardProfile,
        legacyVerifiers: e.legacyRegistered ? [bcryptClaimer] : [],
      });
      if (typeof e.expected === "boolean") {
        expect(hasher.needsRehash(e.encoded)).toBe(e.expected);
      } else {
        try {
          hasher.needsRehash(e.encoded);
          throw new Error("expected throw");
        } catch (err) {
          expect(err).toBeInstanceOf(ArgonGuardError);
          expect((err as ArgonGuardError).reason).toBe(e.expected.reason);
        }
      }
    });
  }
});
