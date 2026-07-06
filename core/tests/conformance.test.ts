import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { randomBytes, timingSafeEqual as nodeTimingSafeEqual } from "node:crypto";
import { hashRaw as nodeHashRaw } from "@node-rs/argon2";
import { describe, expect, it } from "vitest";
import {
  ArgonGuardCoreHasher,
  ArgonGuardError,
  decodeCanonicalBase64,
  encodeBase64NoPad,
  encodePhc,
  MalformedHashError,
  PolicyViolationError,
  UnsupportedAlgorithmError,
  type Argon2Provider,
  type ArgonGuardProfile,
  type CryptoPrimitives,
  type LegacyPasswordVerifier,
} from "../src/index.js";

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), "../../spec/vectors/v1");
const load = (name: string) => JSON.parse(readFileSync(join(VECTORS, name), "utf8")).entries as any[];
const bytes = (hex: string) => new Uint8Array(Buffer.from(hex, "hex"));
const utf8 = (hex: string) => Buffer.from(hex, "hex").toString("utf8");

// 平台注入：以 @node-rs/argon2 為引擎、node:crypto 為 crypto primitive
const engine: Argon2Provider = {
  async hashRaw(password, salt, m, t, p, tagLength) {
    return nodeHashRaw(Buffer.from(password), {
      salt: Buffer.from(salt),
      memoryCost: m, timeCost: t, parallelism: p, outputLen: tagLength,
      algorithm: 2, version: 1, // Algorithm.Argon2id, Version.V0x13（避開 const enum + isolatedModules）
    } as Parameters<typeof nodeHashRaw>[1]);
  },
};
const nodeCrypto: CryptoPrimitives = {
  randomBytes: n => new Uint8Array(randomBytes(n)),
  timingSafeEqual: (a, b) => a.length === b.length && nodeTimingSafeEqual(a, b),
};
const fixedSalt = (salt: Uint8Array): CryptoPrimitives => ({ randomBytes: () => salt, timingSafeEqual: nodeCrypto.timingSafeEqual });
const bcryptClaimer: LegacyPasswordVerifier = { canHandle: e => e.startsWith("$2b$"), verify: () => false };

describe("core base64（RFC 4648 no-pad canonical）", () => {
  it("round-trip 任意位元組", () => {
    for (const arr of [[0], [255], [0, 255, 128, 1], [1, 2, 3, 4, 5, 6, 7], [17, 166, 79, 230, 118]]) {
      const u = new Uint8Array(arr);
      expect([...decodeCanonicalBase64(encodeBase64NoPad(u))]).toEqual(arr);
    }
  });
  it("拒絕 padding / base64url / 非法字元 / mod4==1", () => {
    for (const bad of ["AAA=", "AA==", "ab_d", "ab-d", "A", "AAAAA", "!!!!"]) {
      expect(() => decodeCanonicalBase64(bad)).toThrow(MalformedHashError);
    }
  });
  it("拒絕非 canonical（trailing bits 非零）", () => {
    // "IaZ" 尾端 6-bit 有非零 trailing bits 的變體：用一個已知非 canonical 字串
    expect(() => decodeCanonicalBase64("IB")).toThrow(); // 'I'=8,'B'=1 → trailing bits 非零
  });
});

describe("core deterministic 向量（hashPassword 與四語言 bit-identical）", () => {
  for (const e of load("deterministic.json")) {
    it(e.id, async () => {
      const hasher = new ArgonGuardCoreHasher({ engine, crypto: fixedSalt(bytes(e.saltHex)), profile: e.profile as ArgonGuardProfile });
      expect(await hasher.hashPassword(utf8(e.passwordHex))).toBe(e.encoded);
    });
  }
});

describe("core verify 向量", () => {
  const hasher = new ArgonGuardCoreHasher({ engine, crypto: nodeCrypto });
  for (const e of load("verify.json")) {
    it(e.id, async () => {
      expect(await hasher.verifyPassword(utf8(e.passwordHex), e.encoded)).toBe(e.expected);
    });
  }
});

describe("core reject 向量（typed error + reason）", () => {
  const hasher = new ArgonGuardCoreHasher({ engine, crypto: nodeCrypto });
  const errorClass: Record<string, unknown> = {
    MalformedHash: MalformedHashError,
    PolicyViolation: PolicyViolationError,
    UnsupportedAlgorithm: UnsupportedAlgorithmError,
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

describe("core needs-rehash 向量", () => {
  for (const e of load("needs-rehash.json")) {
    it(e.id, () => {
      const hasher = new ArgonGuardCoreHasher({
        engine, crypto: nodeCrypto,
        profile: e.activeProfile as ArgonGuardProfile,
        legacyVerifiers: e.legacyRegistered ? [bcryptClaimer] : [],
      });
      // expected 可為 boolean，或 { error, reason }（毀損/非 argon2id 未認領時拋錯，不折疊成 true）
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

describe("engine-raw 向量（tagLen≠32 / 低記憶體 edge-safe，engine 層 hashRaw）", () => {
  for (const e of load("engine-raw.json")) {
    it(e.id, async () => {
      const salt = bytes(e.saltHex);
      const tag = await engine.hashRaw(bytes(e.passwordHex), salt, e.m, e.t, e.p, e.tagLen);
      expect(encodePhc(e.m, e.t, e.p, salt, tag)).toBe(e.encoded);
    });
  }
});
