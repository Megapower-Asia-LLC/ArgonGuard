import { ArgonGuardCoreHasher, type ArgonGuardProfile, type CoreHasherDeps, type LegacyPasswordVerifier } from "@argonguard/core";
import { NodeRsArgon2Provider } from "./engine/nodeRsArgon2Provider.js";
import { nodeCryptoPrimitives } from "./nodeCrypto.js";

/** ArgonGuardPasswordHasher 建構選項（SPEC §6.4 L1）。 */
export interface ArgonGuardPasswordHasherOptions {
  /** 強度檔位（預設 "default"）。 */
  profile?: ArgonGuardProfile;
  /** Legacy verifier 有序清單；建構時複製為不可變（SPEC §6.4）。 */
  legacyVerifiers?: LegacyPasswordVerifier[];
}

/**
 * ArgonGuard 密碼雜湊器（Node.js 平台套件）。規格層委由 @argonguard/core，
 * 引擎注入 @node-rs/argon2、CSPRNG 與 constant-time 注入 node:crypto。
 * 公開 API 與 API 語意跟隨四語言 baseline，未因 core 重構而變。
 */
export class ArgonGuardPasswordHasher {
  readonly #core: ArgonGuardCoreHasher;

  constructor(options?: ArgonGuardPasswordHasherOptions) {
    const deps: CoreHasherDeps = {
      engine: new NodeRsArgon2Provider(),
      crypto: nodeCryptoPrimitives,
    };
    // exactOptionalPropertyTypes：只有提供時才賦值，不傳 undefined
    if (options?.profile !== undefined) deps.profile = options.profile;
    if (options?.legacyVerifiers !== undefined) deps.legacyVerifiers = options.legacyVerifiers;
    this.#core = new ArgonGuardCoreHasher(deps);
  }

  /** 現行 active 檔位。 */
  get activeProfile(): ArgonGuardProfile {
    return this.#core.activeProfile;
  }

  /** 產生 active 檔位＋每筆 CSPRNG salt 的 PHC 字串。**async**。 */
  hashPassword(password: string): Promise<string> {
    return this.#core.hashPassword(password);
  }

  /** 驗證密碼；false＝密碼不符，其餘 typed error。constant-time。**async**。 */
  verifyPassword(password: string, encodedHash: string): Promise<boolean> {
    return this.#core.verifyPassword(password, encodedHash);
  }

  /** 是否需要 rehash（SPEC §6.3）。**同步**。 */
  needsRehash(encodedHash: string): boolean {
    return this.#core.needsRehash(encodedHash);
  }
}
