/**
 * ArgonGuard typed error（SPEC §7）。五個類別、每個錯誤攜帶機器可讀 reason code
 * （字串以 spec/reason-codes.json 為權威）。訊息不含密碼、salt 或 tag。
 */
export class ArgonGuardError extends Error {
  /** 機器可讀 reason code，跨語言 bit-identical。 */
  readonly reason: string;

  constructor(reason: string, message: string) {
    super(message);
    this.name = new.target.name;
    this.reason = reason;
  }
}

/** 無法以嚴格文法解析為 PHC argon2id 字串（SPEC §7 MalformedHash）。 */
export class MalformedHashError extends ArgonGuardError {
  constructor(reason: string) {
    super(reason, `Encoded hash is malformed (${reason}).`);
    this.name = "MalformedHashError";
  }
}

/** 可解析但演算法非 argon2id，且無 legacy verifier 認領（SPEC §7）。 */
export class UnsupportedAlgorithmError extends ArgonGuardError {
  constructor(reason: string) {
    super(reason, `Hash algorithm is not supported (${reason}).`);
    this.name = "UnsupportedAlgorithmError";
  }
}

/** 合法 argon2id 但參數落在驗證政策之外，且無 legacy verifier 認領（SPEC §4/§7）。 */
export class PolicyViolationError extends ArgonGuardError {
  constructor(reason: string) {
    super(reason, `Hash parameters violate the verification policy (${reason}).`);
    this.name = "PolicyViolationError";
  }
}

/** 密碼輸入違反輸入正規化規則（SPEC §5/§7）。 */
export class InvalidInputError extends ArgonGuardError {
  constructor(reason: string) {
    super(reason, `Password input is invalid (${reason}).`);
    this.name = "InvalidInputError";
  }
}

/** 執行環境無法提供 argon2id（SPEC §7；Node 引擎為預編譯原生模組，正常情況不會發生）。 */
export class UnsupportedEnvironmentError extends ArgonGuardError {
  constructor(reason: string) {
    super(reason, `Environment cannot provide argon2id (${reason}).`);
    this.name = "UnsupportedEnvironmentError";
  }
}
