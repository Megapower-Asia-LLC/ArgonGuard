/**
 * 內部引擎邊界（SPEC §8.5）：密碼學層委外、可抽換。
 * 引擎型別不得洩漏到公開 API（不從 index.ts 匯出）。
 * 由平台套件實作（node: @node-rs/argon2；edge: argon2id WASM）並於建構 hasher 時注入。
 */
export interface Argon2Provider {
  /** Argon2id raw tag。m 單位 KiB（spec/engine-units.json）。回 Uint8Array（平台無關）。 */
  hashRaw(
    password: Uint8Array,
    salt: Uint8Array,
    m: number,
    t: number,
    p: number,
    tagLength: number,
  ): Promise<Uint8Array>;
}
