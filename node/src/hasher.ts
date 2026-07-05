import { randomBytes, timingSafeEqual } from "node:crypto";
import { NodeRsArgon2Provider } from "./engine/nodeRsArgon2Provider.js";
import type { Argon2Provider } from "./engine/provider.js";
import { MalformedHashError, PolicyViolationError, UnsupportedAlgorithmError } from "./errors.js";
import { validatePassword } from "./input.js";
import type { LegacyPasswordVerifier } from "./legacy.js";
import { encodePhc, parsePhc, tryGetAlgorithm, type PhcHash } from "./phc.js";
import { checkPolicy, MAX_ENCODED_LENGTH, REQUIRED_VERSION } from "./policy.js";
import { profileParameters, type ArgonGuardProfile, type ProfileParameters } from "./profiles.js";
import { ReasonCodes } from "./reasonCodes.js";

/** ArgonGuardPasswordHasher 建構選項（SPEC §6.4 L1）。 */
export interface ArgonGuardPasswordHasherOptions {
  /** 強度檔位（預設 "default"）。 */
  profile?: ArgonGuardProfile;
  /** Legacy verifier 有序清單；建構時複製為不可變（SPEC §6.4）。 */
  legacyVerifiers?: LegacyPasswordVerifier[];
}

/**
 * ArgonGuard 密碼雜湊器（Node.js 實作；跟隨 .NET 參考實作 baseline）。
 * 標準升級流程（SPEC §6.1）：
 * ```ts
 * if (await hasher.verifyPassword(pw, stored)) {
 *   if (hasher.needsRehash(stored)) store(await hasher.hashPassword(pw));
 *   loginOk();
 * }
 * ```
 */
export class ArgonGuardPasswordHasher {
  /** 現行 active 檔位。 */
  readonly activeProfile: ArgonGuardProfile;

  readonly #active: ProfileParameters;
  readonly #legacyVerifiers: readonly LegacyPasswordVerifier[]; // 建構時複製，之後不可變（SPEC L1）
  readonly #engine: Argon2Provider;

  constructor(options?: ArgonGuardPasswordHasherOptions) {
    const profile = options?.profile ?? "default";
    this.activeProfile = profile;
    this.#active = profileParameters(profile);
    this.#legacyVerifiers = copyVerifiers(options?.legacyVerifiers);
    this.#engine = new NodeRsArgon2Provider();
  }

  /** 產生 active 檔位＋每筆獨立 CSPRNG 16-byte salt 的 PHC 字串（SPEC §2、§6.1）。 */
  async hashPassword(password: string): Promise<string> {
    const passwordBytes = validatePassword(password);
    const salt = randomBytes(this.#active.saltBytes);
    const tag = await this.#engine.hashRaw(passwordBytes, salt, this.#active.m, this.#active.t, this.#active.p, this.#active.tagBytes);
    return encodePhc(this.#active.m, this.#active.t, this.#active.p, salt, tag);
  }

  /**
   * 驗證密碼（SPEC §6.2 dispatch）。回傳 false 只有一個意思＝格式合法、政策合規、密碼不符；
   * 其餘一律 typed error（SPEC V1）。tag 比對 constant-time（SPEC §8.1）。
   */
  async verifyPassword(password: string, encodedHash: string): Promise<boolean> {
    const passwordBytes = validatePassword(password);
    if (typeof encodedHash !== "string") throw new MalformedHashError(ReasonCodes.NotPhc);

    // SPEC §6.2 步驟 2：解析前長度預檢
    if (encodedHash.length > MAX_ENCODED_LENGTH) {
      throw new MalformedHashError(ReasonCodes.EncodedTooLong);
    }

    // §6.2 3b 前置：演算法 token 判斷（非 argon2id 不套 argon2 嚴格文法；baseline §1）
    const algorithm = tryGetAlgorithm(encodedHash);
    if (algorithm !== "argon2id") {
      const claimed = this.#findClaimer(encodedHash);
      if (claimed !== null) return claimed.verify(password, encodedHash);
      throw algorithm === null
        ? new MalformedHashError(ReasonCodes.NotPhc)
        : new UnsupportedAlgorithmError(ReasonCodes.UnsupportedAlgorithm);
    }

    let parsed: PhcHash;
    try {
      parsed = parsePhc(encodedHash);
    } catch (error) {
      // §6.2 3b：argon2id 但嚴格文法解析失敗 → legacy；無人認領 → 原 MalformedHash
      if (error instanceof MalformedHashError) {
        const claimed = this.#findClaimer(encodedHash);
        if (claimed !== null) return claimed.verify(password, encodedHash);
      }
      throw error;
    }

    const violation = checkPolicy(parsed);
    if (violation !== null) {
      // §6.2 3a：out-of-policy argon2id → 顯式註冊的 legacy 才可認領（看得見的 opt-in）
      const claimed = this.#findClaimer(encodedHash);
      if (claimed !== null) return claimed.verify(password, encodedHash);
      throw new PolicyViolationError(violation);
    }

    const recomputed = await this.#engine.hashRaw(passwordBytes, parsed.salt, parsed.m, parsed.t, parsed.p, parsed.tag.length);
    // 長度相同由建構保證（outputLen = parsed.tag.length）；timingSafeEqual 為 constant-time
    return timingSafeEqual(parsed.tag, recomputed);
  }

  /**
   * 是否需要 rehash（SPEC §6.3）：任一欄位與 active 檔位不同即 true（含「更強」）。
   * 純 parse-and-compare、不做雜湊、無 DoS 面（N4）。同步 API（跨語言形狀差異為刻意設計）。
   */
  needsRehash(encodedHash: string): boolean {
    if (typeof encodedHash !== "string") throw new MalformedHashError(ReasonCodes.NotPhc);
    if (encodedHash.length > MAX_ENCODED_LENGTH) {
      throw new MalformedHashError(ReasonCodes.EncodedTooLong);
    }

    const algorithm = tryGetAlgorithm(encodedHash);
    if (algorithm !== "argon2id") {
      // SPEC §6.3 N2：legacy 認領恆 true
      if (this.#findClaimer(encodedHash) !== null) return true;
      throw algorithm === null
        ? new MalformedHashError(ReasonCodes.NotPhc)
        : new UnsupportedAlgorithmError(ReasonCodes.UnsupportedAlgorithm);
    }

    let parsed: PhcHash;
    try {
      parsed = parsePhc(encodedHash);
    } catch (error) {
      // SPEC §6.3 N3：無人認領＝資料毀損，不得折疊成 true
      if (error instanceof MalformedHashError && this.#findClaimer(encodedHash) !== null) return true;
      throw error;
    }

    // 精確參數比對（baseline §5：version、keyid/data、m、t、p、salt/tag 長度全部相等才 false）
    return (
      parsed.version !== REQUIRED_VERSION ||
      parsed.hasKeyid ||
      parsed.hasData ||
      parsed.m !== this.#active.m ||
      parsed.t !== this.#active.t ||
      parsed.p !== this.#active.p ||
      parsed.salt.length !== this.#active.saltBytes ||
      parsed.tag.length !== this.#active.tagBytes
    );
  }

  /** 依序詢問 legacy verifiers，回傳第一個認領者（SPEC §6.2：第一個認領者裁決）。 */
  #findClaimer(encodedHash: string): LegacyPasswordVerifier | null {
    for (const verifier of this.#legacyVerifiers) {
      if (verifier.canHandle(encodedHash)) return verifier;
    }
    return null;
  }
}

function copyVerifiers(verifiers: LegacyPasswordVerifier[] | undefined): readonly LegacyPasswordVerifier[] {
  if (verifiers === undefined || verifiers === null) return Object.freeze([]);
  for (const v of verifiers) {
    if (v === null || v === undefined) {
      throw new TypeError("Legacy verifier list contains null.");
    }
  }
  return Object.freeze([...verifiers]);
}
