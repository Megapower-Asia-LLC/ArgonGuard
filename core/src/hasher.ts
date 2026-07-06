import type { CryptoPrimitives } from "./crypto.js";
import type { Argon2Provider } from "./engine/provider.js";
import { MalformedHashError, PolicyViolationError, UnsupportedAlgorithmError } from "./errors.js";
import { utf8ByteLength, validatePassword } from "./input.js";
import type { LegacyPasswordVerifier } from "./legacy.js";
import { encodePhc, parsePhc, tryGetAlgorithm, type PhcHash } from "./phc.js";
import { checkPolicy, MAX_ENCODED_LENGTH, REQUIRED_VERSION } from "./policy.js";
import { profileParameters, type ArgonGuardProfile, type ProfileParameters } from "./profiles.js";
import { ReasonCodes } from "./reasonCodes.js";

/**
 * Core hasher 依賴（平台注入）。engine（Argon2id 原語）與 crypto（CSPRNG + constant-time）
 * 由平台套件提供：node → @node-rs/argon2 + node:crypto；edge → argon2id WASM + Web Crypto。
 * 公開套件（@argonguard/passwords[-edge]）以此為底、對外只暴露 { profile, legacyVerifiers }。
 */
export interface CoreHasherDeps {
  engine: Argon2Provider;
  crypto: CryptoPrimitives;
  profile?: ArgonGuardProfile;
  legacyVerifiers?: LegacyPasswordVerifier[];
}

/**
 * ArgonGuard 規格層 hasher（平台無關）。三操作語意與四語言 baseline 完全一致
 * （SPEC §6）：verifyPassword 回 false 只代表密碼不符，其餘 typed error；needsRehash 同步、
 * 對毀損資料拋錯不折疊成 true。dispatch 順序見 SPEC §6.2 與 baseline §1。
 */
export class ArgonGuardCoreHasher {
  readonly activeProfile: ArgonGuardProfile;

  readonly #active: ProfileParameters;
  readonly #legacyVerifiers: readonly LegacyPasswordVerifier[];
  readonly #engine: Argon2Provider;
  readonly #crypto: CryptoPrimitives;

  constructor(deps: CoreHasherDeps) {
    const profile = deps.profile ?? "default";
    this.activeProfile = profile;
    this.#active = profileParameters(profile);
    this.#legacyVerifiers = copyVerifiers(deps.legacyVerifiers);
    this.#engine = deps.engine;
    this.#crypto = deps.crypto;
  }

  /** 產生 active 檔位＋每筆獨立 CSPRNG salt 的 PHC 字串（SPEC §2、§6.1）。 */
  async hashPassword(password: string): Promise<string> {
    const passwordBytes = validatePassword(password);
    const salt = this.#crypto.randomBytes(this.#active.saltBytes);
    const tag = await this.#engine.hashRaw(passwordBytes, salt, this.#active.m, this.#active.t, this.#active.p, this.#active.tagBytes);
    return encodePhc(this.#active.m, this.#active.t, this.#active.p, salt, tag);
  }

  /** 驗證密碼（SPEC §6.2 dispatch）。false＝密碼不符；其餘 typed error。tag 比對 constant-time。 */
  async verifyPassword(password: string, encodedHash: string): Promise<boolean> {
    const passwordBytes = validatePassword(password);
    if (typeof encodedHash !== "string") throw new MalformedHashError(ReasonCodes.NotPhc);

    if (utf8ByteLength(encodedHash) > MAX_ENCODED_LENGTH) {
      throw new MalformedHashError(ReasonCodes.EncodedTooLong);
    }

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
      if (error instanceof MalformedHashError) {
        const claimed = this.#findClaimer(encodedHash);
        if (claimed !== null) return claimed.verify(password, encodedHash);
      }
      throw error;
    }

    const violation = checkPolicy(parsed);
    if (violation !== null) {
      const claimed = this.#findClaimer(encodedHash);
      if (claimed !== null) return claimed.verify(password, encodedHash);
      throw new PolicyViolationError(violation);
    }

    const recomputed = await this.#engine.hashRaw(passwordBytes, parsed.salt, parsed.m, parsed.t, parsed.p, parsed.tag.length);
    return this.#crypto.timingSafeEqual(parsed.tag, recomputed);
  }

  /**
   * 是否需要 rehash（SPEC §6.3）：任一欄位與 active 檔位不同即 true（含「更強」）。
   * 純 parse-and-compare、不做雜湊、無 DoS 面。同步 API。
   */
  needsRehash(encodedHash: string): boolean {
    if (typeof encodedHash !== "string") throw new MalformedHashError(ReasonCodes.NotPhc);
    if (utf8ByteLength(encodedHash) > MAX_ENCODED_LENGTH) {
      throw new MalformedHashError(ReasonCodes.EncodedTooLong);
    }

    const algorithm = tryGetAlgorithm(encodedHash);
    if (algorithm !== "argon2id") {
      if (this.#findClaimer(encodedHash) !== null) return true;
      throw algorithm === null
        ? new MalformedHashError(ReasonCodes.NotPhc)
        : new UnsupportedAlgorithmError(ReasonCodes.UnsupportedAlgorithm);
    }

    let parsed: PhcHash;
    try {
      parsed = parsePhc(encodedHash);
    } catch (error) {
      if (error instanceof MalformedHashError && this.#findClaimer(encodedHash) !== null) return true;
      throw error;
    }

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

  /** 依序詢問 legacy verifiers，回傳第一個認領者（SPEC §6.2）。 */
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
