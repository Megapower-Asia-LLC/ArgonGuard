import { encodePhc } from "@argonguard/core";
import { NodeRsArgon2Provider } from "../engine/nodeRsArgon2Provider.js";

/**
 * Conformance 測試專用（不從 index.ts 匯出、不進公開 API）：
 * 固定 salt 重現 deterministic 向量（對應 .NET internal HashPasswordWithSalt）。
 */
export async function hashPasswordWithSaltForConformance(
  passwordBytes: Uint8Array,
  salt: Uint8Array,
  m: number,
  t: number,
  p: number,
  tagLength: number,
): Promise<string> {
  const tag = await new NodeRsArgon2Provider().hashRaw(passwordBytes, salt, m, t, p, tagLength);
  return encodePhc(m, t, p, salt, tag);
}
