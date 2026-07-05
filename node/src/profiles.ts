/** 強度檔位（閉集；SPEC §3）。公開 API 不暴露任何數字參數。 */
export type ArgonGuardProfile = "default" | "high" | "highest";

/** 檔位參數常數（與 spec/engine-units.json 一致；conformance 測試互相印證）。 */
export interface ProfileParameters {
  readonly m: number; // KiB（spec/engine-units.json: node_node_rs_argon2_memoryCost）
  readonly t: number;
  readonly p: number;
  readonly saltBytes: number;
  readonly tagBytes: number;
}

const PROFILES: Readonly<Record<ArgonGuardProfile, ProfileParameters>> = Object.freeze({
  // OWASP 等效最低配置的 canonical 一組（永久哨兵，SPEC §3 P1）
  default: Object.freeze({ m: 19456, t: 2, p: 1, saltBytes: 16, tagBytes: 32 }),
  high: Object.freeze({ m: 65536, t: 2, p: 1, saltBytes: 16, tagBytes: 32 }),
  highest: Object.freeze({ m: 131072, t: 2, p: 1, saltBytes: 16, tagBytes: 32 }),
});

/** 取得檔位參數；未知檔位（執行期非法輸入）拋 RangeError（非 typed error，屬使用錯誤）。 */
export function profileParameters(profile: ArgonGuardProfile): ProfileParameters {
  const parameters = PROFILES[profile];
  if (parameters === undefined) {
    throw new RangeError(`Unknown ArgonGuard profile: ${String(profile)}`);
  }
  return parameters;
}
