/**
 * @argonguard/core — ArgonGuard 規格層（平台無關）。
 *
 * 規格層自寫（PHC parser／policy／needsRehash／base64／constant-time，四語言 bit-identical），
 * 密碼學引擎與 CSPRNG 由平台套件（@argonguard/passwords[-edge]）透過 Argon2Provider ／
 * CryptoPrimitives 注入。此套件本身零 runtime 依賴、不直接對終端使用者暴露公開 hasher API
 * （平台套件負責 wrap 成只吃 { profile, legacyVerifiers } 的公開建構子）。
 */
export { SPEC_VERSION } from "./specVersion.js";
export { ArgonGuardCoreHasher, type CoreHasherDeps } from "./hasher.js";
export type { ArgonGuardProfile, ProfileParameters } from "./profiles.js";
export { profileParameters } from "./profiles.js";
export type { LegacyPasswordVerifier } from "./legacy.js";
export type { Argon2Provider } from "./engine/provider.js";
export { type CryptoPrimitives, webCryptoPrimitives } from "./crypto.js";
export { timingSafeEqual } from "./constantTime.js";
export { encodeBase64NoPad, decodeCanonicalBase64 } from "./base64.js";
// 規格層公用函式（平台套件的 conformance helper / provider 需要；不屬終端公開 API）
export { encodePhc, parsePhc, tryGetAlgorithm, type PhcHash } from "./phc.js";
export { checkPolicy } from "./policy.js";
export { validatePassword, utf8ByteLength } from "./input.js";
export { ReasonCodes } from "./reasonCodes.js";
export {
  ArgonGuardError,
  MalformedHashError,
  UnsupportedAlgorithmError,
  PolicyViolationError,
  InvalidInputError,
  UnsupportedEnvironmentError,
} from "./errors.js";
