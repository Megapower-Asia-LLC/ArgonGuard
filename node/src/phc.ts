import { MalformedHashError } from "./errors.js";
import { ReasonCodes } from "./reasonCodes.js";

/**
 * 嚴格 PHC parser／encoder（SPEC §2、§4 S1–S4；baseline §1/§4）。
 * 文法澄清（跨語言 bit-identical，由 .NET baseline 文件釘死）：
 * 數字欄位僅允許 [0-9]、無正負號、無前導零（單獨 "0" 除外）、位數上限 15（防溢位）；
 * base64 採 RFC 4648 §4 標準字元集、無 padding，且必須 canonical
 * （decode 後 re-encode 必須等於原字串，封死 trailing-bit 可鍛性）；長度 mod 4 == 1 → 非法。
 */

/** 嚴格解析後的 PHC 欄位。algorithm 保留原字串供 dispatch 判斷是否 argon2id。 */
export interface PhcHash {
  readonly algorithm: string;
  readonly version: number | null;
  readonly m: number;
  readonly t: number;
  readonly p: number;
  readonly salt: Buffer;
  readonly tag: Buffer;
  readonly hasKeyid: boolean;
  readonly hasData: boolean;
}

/**
 * 抽出 PHC 演算法 token（dispatch 前置判斷；baseline §1）：字串為 "$<token>$…" 且 token 合法
 * （小寫英數與 '-'）時回傳 token，否則 null。token != "argon2id" → dispatch 走
 * UnsupportedAlgorithm 路徑，不套用 argon2 嚴格文法。
 */
export function tryGetAlgorithm(encoded: string): string | null {
  if (encoded.length < 3 || encoded[0] !== "$") return null;
  const end = encoded.indexOf("$", 1);
  if (end <= 1) return null;
  const token = encoded.substring(1, end);
  return isLowerAlnumDash(token) ? token : null;
}

/** 嚴格解析。失敗拋 MalformedHashError（reason 依 SPEC）。長度預檢（>512）由呼叫端負責。 */
export function parsePhc(encoded: string): PhcHash {
  if (encoded.length === 0 || encoded[0] !== "$") {
    throw new MalformedHashError(ReasonCodes.NotPhc);
  }

  const parts = encoded.split("$");
  // ["", alg, "v=19", params, salt, tag]（有 v）或 ["", alg, params, salt, tag]（缺 v → 政策層 missing_version）
  if (parts.length !== 5 && parts.length !== 6) {
    throw new MalformedHashError(ReasonCodes.NotPhc);
  }

  const algorithm = parts[1]!;
  if (algorithm.length === 0 || !isLowerAlnumDash(algorithm)) {
    throw new MalformedHashError(ReasonCodes.NotPhc);
  }

  let version: number | null = null;
  let paramsIndex = 2;
  if (parts.length === 6) {
    const versionSegment = parts[2]!;
    if (!versionSegment.startsWith("v=")) {
      throw new MalformedHashError(ReasonCodes.NotPhc);
    }
    version = parseNumber(versionSegment.substring(2));
    paramsIndex = 3;
  }

  const { m, t, p, hasKeyid, hasData } = parseParams(parts[paramsIndex]!);
  const salt = decodeCanonicalBase64(parts[paramsIndex + 1]!);
  const tag = decodeCanonicalBase64(parts[paramsIndex + 2]!);
  return { algorithm, version, m, t, p, salt, tag, hasKeyid, hasData };
}

/** 產生端 encoder（SPEC §2 G1–G8）。 */
export function encodePhc(m: number, t: number, p: number, salt: Uint8Array, tag: Uint8Array): string {
  return `$argon2id$v=19$m=${m},t=${t},p=${p}$${encodeBase64NoPad(salt)}$${encodeBase64NoPad(tag)}`;
}

interface ParsedParams {
  m: number;
  t: number;
  p: number;
  hasKeyid: boolean;
  hasData: boolean;
}

function parseParams(paramSegment: string): ParsedParams {
  const tokens = paramSegment.split(",");
  if (tokens.length < 3) {
    throw new MalformedHashError(isPermutedMtp(tokens) ? ReasonCodes.ParamsOutOfOrder : ReasonCodes.NotPhc);
  }

  // 前三個 token 必須依序為 m=、t=、p=（SPEC S1；重排 → params_out_of_order，其他 → not_phc）
  if (!(tokens[0]!.startsWith("m=") && tokens[1]!.startsWith("t=") && tokens[2]!.startsWith("p="))) {
    throw new MalformedHashError(isPermutedMtp(tokens) ? ReasonCodes.ParamsOutOfOrder : ReasonCodes.NotPhc);
  }

  const m = parseNumber(tokens[0]!.substring(2));
  const t = parseNumber(tokens[1]!.substring(2));
  const p = parseNumber(tokens[2]!.substring(2));

  let hasKeyid = false;
  let hasData = false;
  for (let i = 3; i < tokens.length; i++) {
    const token = tokens[i]!;
    if (token.startsWith("keyid=")) hasKeyid = true;
    else if (token.startsWith("data=")) hasData = true;
    else throw new MalformedHashError(ReasonCodes.NotPhc);
  }
  return { m, t, p, hasKeyid, hasData };
}

/** 前三 token 是否為 m/t/p 的重排（區分 params_out_of_order 與 not_phc）。 */
function isPermutedMtp(tokens: string[]): boolean {
  if (tokens.length < 3) return false;
  let seen = 0;
  for (let i = 0; i < 3; i++) {
    const token = tokens[i]!;
    if (token.startsWith("m=")) seen |= 1;
    else if (token.startsWith("t=")) seen |= 2;
    else if (token.startsWith("p=")) seen |= 4;
    else return false;
  }
  return seen === 7;
}

/** 嚴格數字：僅 [0-9]、無前導零（"0" 除外）、位數 ≤15（防溢位；15 位十進位在 2^53 內安全）。 */
function parseNumber(digits: string): number {
  if (digits.length === 0 || digits.length > 15) {
    throw new MalformedHashError(ReasonCodes.NotPhc);
  }
  if (digits.length > 1 && digits[0] === "0") {
    throw new MalformedHashError(ReasonCodes.NotPhc); // 禁前導零（嚴格文法）
  }
  let value = 0;
  for (const c of digits) {
    if (c < "0" || c > "9") {
      throw new MalformedHashError(ReasonCodes.NotPhc);
    }
    value = value * 10 + (c.charCodeAt(0) - 48);
  }
  return value;
}

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function decodeCanonicalBase64(s: string): Buffer {
  if (s.length === 0) {
    throw new MalformedHashError(ReasonCodes.BadBase64);
  }
  for (const c of s) {
    if (!BASE64_ALPHABET.includes(c)) {
      throw new MalformedHashError(ReasonCodes.BadBase64); // 含 '='（padding）、base64url、其他字元一律拒絕
    }
  }
  const rem = s.length % 4;
  if (rem === 1) {
    throw new MalformedHashError(ReasonCodes.BadBase64);
  }
  // 字元集與長度已預檢，Buffer.from 的寬鬆解碼此處等價於嚴格解碼
  const decoded = Buffer.from(s + "=".repeat((4 - rem) % 4), "base64");
  // canonical 檢查：re-encode 必須還原原字串（封死 trailing-bit 可鍛性）
  if (encodeBase64NoPad(decoded) !== s) {
    throw new MalformedHashError(ReasonCodes.BadBase64);
  }
  return decoded;
}

function encodeBase64NoPad(data: Uint8Array): string {
  return Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString("base64").replace(/=+$/, "");
}

function isLowerAlnumDash(s: string): boolean {
  for (const c of s) {
    if (!((c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c === "-")) {
      return false;
    }
  }
  return true;
}
