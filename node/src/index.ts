/**
 * ArgonGuard（Node.js 實作）—— OWASP 合規 Argon2id 密碼雜湊元件。
 * 公開 API 面（SPEC §6）：ArgonGuardPasswordHasher 三操作＋五 typed error＋LegacyPasswordVerifier。
 * 引擎（@node-rs/argon2）藏於內部 provider 邊界，不出現在公開 API（SPEC §8.5）。
 */
export { SPEC_VERSION } from "./specVersion.js";
export { ArgonGuardPasswordHasher, type ArgonGuardPasswordHasherOptions } from "./hasher.js";
export type { ArgonGuardProfile } from "./profiles.js";
export type { LegacyPasswordVerifier } from "./legacy.js";
export {
  ArgonGuardError,
  MalformedHashError,
  UnsupportedAlgorithmError,
  PolicyViolationError,
  InvalidInputError,
  UnsupportedEnvironmentError,
} from "./errors.js";
