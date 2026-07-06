import type { PhcHash } from "./phc.js";
import { ReasonCodes } from "./reasonCodes.js";

/**
 * 驗證端參數政策（SPEC §4）：OWASP frontier 凍結表（地板）＋天花板（DoS 防護）。
 * 純函式、無雜湊運算。常數與 spec/engine-units.json 一致（conformance 互相印證）。
 */

// OWASP frontier（查證 2026-07-05；spec MINOR 才可調整）
function frontierMinM(t: number): number {
  switch (t) {
    case 1: return 47104;
    case 2: return 19456;
    case 3: return 12288;
    case 4: return 9216;
    default: return 7168; // t >= 5
  }
}

export const MAX_M = 262144;
export const MAX_T = 8;
export const MIN_SALT_BYTES = 16;
export const MAX_SALT_BYTES = 64;
export const MIN_TAG_BYTES = 32;
export const MAX_TAG_BYTES = 128;
export const MAX_ENCODED_LENGTH = 512;
export const REQUIRED_VERSION = 19;

/**
 * 政策檢查。回傳 null＝通過；否則回傳 reason code（呼叫端決定 dispatch 或拋錯）。
 * 檢查順序（跨語言一致，baseline §3 釘死）：
 * missing_version → unsupported_version → keyid → data → p_not_one →
 * t_above_ceiling → m_above_ceiling → below_owasp_frontier → salt → tag。
 */
export function checkPolicy(hash: PhcHash): string | null {
  if (hash.version === null) return ReasonCodes.MissingVersion;
  if (hash.version !== REQUIRED_VERSION) return ReasonCodes.UnsupportedVersion;
  if (hash.hasKeyid) return ReasonCodes.KeyidNotAllowed;
  if (hash.hasData) return ReasonCodes.DataNotAllowed;
  if (hash.p !== 1) return ReasonCodes.PNotOne;
  if (hash.t > MAX_T) return ReasonCodes.TAboveCeiling;
  if (hash.m > MAX_M) return ReasonCodes.MAboveCeiling;
  if (hash.t < 1 || hash.m < frontierMinM(hash.t)) return ReasonCodes.BelowOwaspFrontier;
  if (hash.salt.length < MIN_SALT_BYTES || hash.salt.length > MAX_SALT_BYTES) return ReasonCodes.SaltLengthOutOfRange;
  if (hash.tag.length < MIN_TAG_BYTES || hash.tag.length > MAX_TAG_BYTES) return ReasonCodes.TagLengthOutOfRange;
  return null;
}
