/** 強度檔位（閉集；SPEC §3）。公開 API 不暴露任何數字參數。 */
export type ArgonGuardProfile = "default" | "high" | "highest";

/** 檔位參數常數（與 spec/engine-units.json 一致；conformance 測試互相印證）。 */
export interface ProfileParameters {
  readonly m: number; // KiB
  readonly t: number;
  readonly p: number;
  readonly saltBytes: number;
  readonly tagBytes: number;
}

// 用 Map（非物件字面量）避免原型鏈鍵（__proto__/constructor/toString…）繞過閉集驗證——
// Map.get 只回自有 entry、未知 key 一律 undefined（M5 對抗審查修正）。
const PROFILES: ReadonlyMap<ArgonGuardProfile, ProfileParameters> = new Map<ArgonGuardProfile, ProfileParameters>([
  ["default", Object.freeze({ m: 19456, t: 2, p: 1, saltBytes: 16, tagBytes: 32 })],
  ["high", Object.freeze({ m: 65536, t: 2, p: 1, saltBytes: 16, tagBytes: 32 })],
  ["highest", Object.freeze({ m: 131072, t: 2, p: 1, saltBytes: 16, tagBytes: 32 })],
]);

/** 取得檔位參數；未知檔位（執行期非法輸入，含原型鏈鍵）拋 RangeError（非 typed error，屬使用錯誤）。 */
export function profileParameters(profile: ArgonGuardProfile): ProfileParameters {
  const parameters = PROFILES.get(profile);
  if (parameters === undefined) {
    throw new RangeError(`Unknown ArgonGuard profile: ${String(profile)}`);
  }
  return parameters;
}
