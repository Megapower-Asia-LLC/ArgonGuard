/**
 * 內部引擎邊界（SPEC §8.5）：密碼學層委外、可抽換。
 * 引擎型別不得洩漏到公開 API（本模組不從 index.ts 匯出）。
 */
export interface Argon2Provider {
  /** Argon2id raw tag（真背景執行緒）。m 單位 KiB（spec/engine-units.json）。 */
  hashRaw(password: Uint8Array, salt: Uint8Array, m: number, t: number, p: number, tagLength: number): Promise<Buffer>;
}
