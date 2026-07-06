import { decodeCanonicalBase64, encodeBase64NoPad } from "./base64.js";
import { MalformedHashError } from "./errors.js";
import { ReasonCodes } from "./reasonCodes.js";

/**
 * 嚴格 PHC parser／encoder（SPEC §2、§4 S1–S4；baseline §1/§4）。平台無關版本：
 * salt/tag 為 Uint8Array，base64 由 ./base64.ts 提供（純 JS，四語言／edge bit-identical）。
 * 數字欄位僅允許 [0-9]、無正負號、無前導零（"0" 除外）、位數上限 15；base64 canonical no-pad。
 */

/** 嚴格解析後的 PHC 欄位。algorithm 保留原字串供 dispatch 判斷是否 argon2id。 */
export interface PhcHash {
  readonly algorithm: string;
  readonly version: number | null;
  readonly m: number;
  readonly t: number;
  readonly p: number;
  readonly salt: Uint8Array;
  readonly tag: Uint8Array;
  readonly hasKeyid: boolean;
  readonly hasData: boolean;
}

/**
 * 抽出 PHC 演算法 token（dispatch 前置判斷；baseline §1）。token != "argon2id" → dispatch 走
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

/** 嚴格數字：僅 [0-9]、無前導零（"0" 除外）、位數 ≤15（防溢位）。 */
function parseNumber(digits: string): number {
  if (digits.length === 0 || digits.length > 15) {
    throw new MalformedHashError(ReasonCodes.NotPhc);
  }
  if (digits.length > 1 && digits[0] === "0") {
    throw new MalformedHashError(ReasonCodes.NotPhc);
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

function isLowerAlnumDash(s: string): boolean {
  for (const c of s) {
    if (!((c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c === "-")) {
      return false;
    }
  }
  return true;
}
