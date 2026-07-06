/**
 * 引擎邊界（SPEC §8.5）：密碼學層委外、可抽換。由平台套件實作
 * （node: @node-rs/argon2；edge: argon2id WASM）並於建構 hasher 時注入。
 *
 * core 是「平台 SDK」，匯出此型別**供平台套件實作引擎**；但終端公開套件
 * （@argonguard/passwords[-edge]）**不得 re-export 此型別**——終端 API 面只有
 * { profile, legacyVerifiers }，引擎型別不進終端使用者的公開 API（PPLX edge 審核 #3）。
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
