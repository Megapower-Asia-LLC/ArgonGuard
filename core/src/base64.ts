import { MalformedHashError } from "./errors.js";
import { ReasonCodes } from "./reasonCodes.js";

/**
 * 平台無關的 RFC 4648 §4 標準 base64（字母表含 `+/`）、**無 padding**、canonical。
 *
 * 為何自寫、不用 `atob`/`btoa`（PPLX edge 審核）：`atob`/`btoa` 是 Latin-1、非 binary-safe
 * （對 >0xFF 拋錯、`String.fromCharCode(...)` 大 buffer 會 stack overflow）、且輸出帶 `=` padding
 * 與 URL-safe 混用風險。core 走純查表實作，四語言／edge bit-identical。
 */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// 反查表：ASCII code → 6-bit 值；非法字元為 255
const LOOKUP = /* @__PURE__ */ (() => {
  const table = new Uint8Array(128).fill(255);
  for (let i = 0; i < ALPHABET.length; i++) table[ALPHABET.charCodeAt(i)] = i;
  return table;
})();

/** 無 padding 標準 base64 編碼。 */
export function encodeBase64NoPad(data: Uint8Array): string {
  let out = "";
  const len = data.length;
  for (let i = 0; i < len; i += 3) {
    const b0 = data[i]!;
    const b1 = i + 1 < len ? data[i + 1]! : 0;
    const b2 = i + 2 < len ? data[i + 2]! : 0;
    out += ALPHABET[b0 >> 2];
    out += ALPHABET[((b0 & 3) << 4) | (b1 >> 4)];
    if (i + 1 < len) out += ALPHABET[((b1 & 15) << 2) | (b2 >> 6)];
    if (i + 2 < len) out += ALPHABET[b2 & 63];
  }
  return out;
}

/**
 * 嚴格 canonical 解碼（SPEC §2）：字母表外字元（含 `=` padding、base64url）一律拒絕；
 * 長度 mod 4 == 1 非法；decode 後 re-encode 必須還原原字串（封死 trailing-bit 可鍛性）。
 * 失敗拋 MalformedHashError(bad_base64)。
 */
export function decodeCanonicalBase64(s: string): Uint8Array {
  if (s.length === 0) throw new MalformedHashError(ReasonCodes.BadBase64);
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code >= 128 || LOOKUP[code] === 255) throw new MalformedHashError(ReasonCodes.BadBase64);
  }
  const rem = s.length % 4;
  if (rem === 1) throw new MalformedHashError(ReasonCodes.BadBase64);

  const outLen = Math.floor((s.length * 3) / 4);
  const out = new Uint8Array(outLen);
  let o = 0;
  for (let i = 0; i < s.length; i += 4) {
    const c0 = LOOKUP[s.charCodeAt(i)]!;
    const c1 = LOOKUP[s.charCodeAt(i + 1)]!;
    const c2 = i + 2 < s.length ? LOOKUP[s.charCodeAt(i + 2)]! : 0;
    const c3 = i + 3 < s.length ? LOOKUP[s.charCodeAt(i + 3)]! : 0;
    out[o++] = (c0 << 2) | (c1 >> 4);
    if (i + 2 < s.length) out[o++] = ((c1 & 15) << 4) | (c2 >> 2);
    if (i + 3 < s.length) out[o++] = ((c2 & 3) << 6) | c3;
  }
  const decoded = out.subarray(0, o);
  // canonical：re-encode 必須等於原字串
  if (encodeBase64NoPad(decoded) !== s) throw new MalformedHashError(ReasonCodes.BadBase64);
  return decoded;
}
