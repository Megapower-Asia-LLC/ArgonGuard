/**
 * @argonguard/passwords — ArgonGuard Node.js 平台套件。
 * 規格層委由 @argonguard/core（PHC parser／policy／needsRehash，四語言 bit-identical），
 * 引擎為 @node-rs/argon2、CSPRNG／constant-time 為 node:crypto（藏於 internal provider）。
 */
export { SPEC_VERSION } from "@argonguard/core";
export { ArgonGuardPasswordHasher, type ArgonGuardPasswordHasherOptions } from "./hasher.js";
export type { ArgonGuardProfile, LegacyPasswordVerifier } from "@argonguard/core";
export {
  ArgonGuardError,
  MalformedHashError,
  UnsupportedAlgorithmError,
  PolicyViolationError,
  InvalidInputError,
  UnsupportedEnvironmentError,
} from "@argonguard/core";
