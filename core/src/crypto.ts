import { timingSafeEqual as defaultTimingSafeEqual } from "./constantTime.js";

/**
 * 平台密碼學基元注入邊界。由平台套件提供：
 * - node：`node:crypto` 的 `randomBytes` ＋ `timingSafeEqual`
 * - edge：Web Crypto 的 `crypto.getRandomValues` ＋ core 預設 constant-time
 *
 * `randomBytes` 為 CSPRNG（SPEC §8.2）。實作須保證：n > 0 時回傳長度恰為 n 的 Uint8Array；
 * 無法提供亂數時 throw（不得回傳弱亂數）。edge 若用 `crypto.getRandomValues`，單次上限 65536 bytes
 * （salt 16 bytes 遠低於此，不觸發 QuotaExceededError）。
 */
export interface CryptoPrimitives {
  randomBytes(length: number): Uint8Array;
  timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean;
}

/**
 * 以 Web Crypto 組出的平台無關預設實作（edge 直接可用；node 覆寫 timingSafeEqual 為原生）。
 * getRandomValues 在 workerd / 瀏覽器 / Node 20+ 皆為全域可用。
 */
export const webCryptoPrimitives: CryptoPrimitives = {
  randomBytes(length: number): Uint8Array {
    const buf = new Uint8Array(length);
    crypto.getRandomValues(buf);
    return buf;
  },
  timingSafeEqual: defaultTimingSafeEqual,
};
