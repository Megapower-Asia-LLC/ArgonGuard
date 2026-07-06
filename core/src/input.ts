import { InvalidInputError } from "./errors.js";
import { ReasonCodes } from "./reasonCodes.js";

const textEncoder = new TextEncoder();

/**
 * SPEC §5 輸入規則。檢查優先序（跨語言一致，baseline §2 釘死）：
 * well-formed（unpaired surrogate）→ empty → too_long（>1024 UTF-8 bytes）→ contains NUL。
 *
 * 必須先 isWellFormed()（ES2024；Node 20+／workerd／現代瀏覽器皆有）：TextEncoder 對
 * unpaired surrogate 不會拋錯、會靜默替換成 U+FFFD，所以 well-formed 檢查必須先行。
 */
export function validatePassword(password: string): Uint8Array {
  if (typeof password !== "string") {
    // 與 .NET baseline 對齊：null 輸入視為 empty
    throw new InvalidInputError(ReasonCodes.PasswordEmpty);
  }
  if (!password.isWellFormed()) {
    throw new InvalidInputError(ReasonCodes.PasswordNotWellFormed);
  }
  const bytes = textEncoder.encode(password);
  if (bytes.length === 0) throw new InvalidInputError(ReasonCodes.PasswordEmpty);
  if (bytes.length > 1024) throw new InvalidInputError(ReasonCodes.PasswordTooLong);
  if (bytes.includes(0)) throw new InvalidInputError(ReasonCodes.PasswordContainsNul);
  return bytes;
}

/** UTF-8 位元組長度（平台無關取代 Buffer.byteLength；SPEC §6.2 encoded 長度預檢用）。 */
export function utf8ByteLength(s: string): number {
  return textEncoder.encode(s).length;
}
