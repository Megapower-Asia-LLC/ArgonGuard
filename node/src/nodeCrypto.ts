import { randomBytes, timingSafeEqual } from "node:crypto";
import type { CryptoPrimitives } from "@argonguard/core";

/**
 * Node 平台密碼學基元（注入 core）：node:crypto 的 CSPRNG 與原生 constant-time 比對。
 * timingSafeEqual 需長度相同（node 原生對不等長會拋 RangeError），故先比長度。
 */
export const nodeCryptoPrimitives: CryptoPrimitives = {
  randomBytes: (length: number): Uint8Array => randomBytes(length),
  timingSafeEqual: (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && timingSafeEqual(a, b),
};
