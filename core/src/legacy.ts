/**
 * Legacy 格式驗證擴充點（SPEC §6.4）。僅能於建構 hasher 時以不可變有序清單注入；
 * 執行期動態註冊在 API 形狀上不可能。核心不內建任何 legacy 演算法實作；bcrypt 等範例見文件。
 */
export interface LegacyPasswordVerifier {
  /** 廉價前綴判斷：此 verifier 是否認領該字串。不得執行昂貴運算。 */
  canHandle(encodedHash: string): boolean;

  /** 驗證密碼。僅在 canHandle 回 true 時被呼叫。可為同步或非同步（Node 慣例）。 */
  verify(password: string, encodedHash: string): boolean | Promise<boolean>;
}
