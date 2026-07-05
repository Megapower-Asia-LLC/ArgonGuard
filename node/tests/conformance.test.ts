import { describe, expect, it } from "vitest";
import {
  ArgonGuardError,
  ArgonGuardPasswordHasher,
  InvalidInputError,
  MalformedHashError,
  PolicyViolationError,
  UnsupportedAlgorithmError,
  UnsupportedEnvironmentError,
  type ArgonGuardProfile,
  type LegacyPasswordVerifier,
} from "../src/index.js";
import { hashPasswordWithSaltForConformance } from "../src/internal/conformance.js";
import { hex, utf8, vectorEntries, vectorEntry } from "./vectors.js";

/** 凍結向量 conformance（SPEC §10）。任一紅燈＝不合規。 */

const ERROR_TYPES: Record<string, new (reason: string) => ArgonGuardError> = {
  MalformedHash: MalformedHashError,
  UnsupportedAlgorithm: UnsupportedAlgorithmError,
  PolicyViolation: PolicyViolationError,
  InvalidInput: InvalidInputError,
  UnsupportedEnvironment: UnsupportedEnvironmentError,
};

async function captureRejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error("expected promise to reject");
}

function captureThrow(fn: () => unknown): unknown {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error("expected function to throw");
}

function expectTypedError(error: unknown, expectedError: string, expectedReason: string): void {
  expect(error).toBeInstanceOf(ERROR_TYPES[expectedError]!);
  expect((error as ArgonGuardError).reason).toBe(expectedReason);
}

class FakeBcryptVerifier implements LegacyPasswordVerifier {
  canHandle(encodedHash: string): boolean {
    return encodedHash.startsWith("$2b$");
  }

  verify(_password: string, _encodedHash: string): boolean {
    return false;
  }
}

describe("deterministic vectors (fixed salt, byte-identical encoded)", () => {
  for (const e of vectorEntries("deterministic.json")) {
    it(`${e.id}: encode matches frozen vector`, async () => {
      const encoded = await hashPasswordWithSaltForConformance(
        hex(e.passwordHex),
        hex(e.saltHex),
        e.m,
        e.t,
        e.p,
        e.tagLen,
      );
      expect(encoded).toBe(e.encoded);
    });

    it(`${e.id}: verifies true`, async () => {
      const hasher = new ArgonGuardPasswordHasher();
      await expect(hasher.verifyPassword(utf8(hex(e.passwordHex)), e.encoded)).resolves.toBe(true);
    });
  }
});

describe("verify vectors", () => {
  for (const e of vectorEntries("verify.json")) {
    it(`${e.id}: verify === ${e.expected}`, async () => {
      const hasher = new ArgonGuardPasswordHasher();
      await expect(hasher.verifyPassword(utf8(hex(e.passwordHex)), e.encoded)).resolves.toBe(e.expected);
    });
  }
});

describe("reject vectors (exact typed error + reason)", () => {
  for (const e of vectorEntries("reject.json")) {
    it(`${e.id}: ${e.expectedError}/${e.expectedReason}`, async () => {
      const hasher = new ArgonGuardPasswordHasher();
      const error = await captureRejection(hasher.verifyPassword(utf8(hex(e.passwordHex)), e.encoded));
      expectTypedError(error, e.expectedError, e.expectedReason);
    });
  }
});

describe("needs-rehash truth table", () => {
  for (const e of vectorEntries("needs-rehash.json")) {
    it(`${e.id}`, () => {
      const options: {
        profile: ArgonGuardProfile;
        legacyVerifiers?: LegacyPasswordVerifier[];
      } = { profile: e.activeProfile as ArgonGuardProfile };
      if (e.legacyRegistered) options.legacyVerifiers = [new FakeBcryptVerifier()];
      const hasher = new ArgonGuardPasswordHasher(options);

      if (typeof e.expected === "boolean") {
        expect(hasher.needsRehash(e.encoded)).toBe(e.expected);
      } else {
        const error = captureThrow(() => hasher.needsRehash(e.encoded));
        expectTypedError(error, e.expected.error, e.expected.reason);
      }
    });
  }
});

describe("input-limits vectors", () => {
  for (const e of vectorEntries("input-limits.json")) {
    it(`${e.id}`, async () => {
      const hasher = new ArgonGuardPasswordHasher();

      if (e.refA !== undefined) {
        // NFC vs NFD：兩筆 deterministic 向量的 encoded 必須不同（無 Unicode 正規化）
        const a = vectorEntry("deterministic.json", e.refA).encoded;
        const b = vectorEntry("deterministic.json", e.refB).encoded;
        expect(a).not.toBe(b);
        return;
      }

      let password: string;
      if (e.stringInput !== undefined) {
        // "\\uD800ab" 標記法 → 還原為含 lone surrogate 的 JS 字串
        const raw: string = e.stringInput;
        expect(raw.startsWith("\\uD800")).toBe(true);
        password = "\uD800" + raw.substring(6);
      } else {
        password = utf8(hex(e.passwordHex));
      }

      if (e.expected === "ok") {
        const encoded = await hasher.hashPassword(password);
        await expect(hasher.verifyPassword(password, encoded)).resolves.toBe(true);
      } else {
        const error = await captureRejection(hasher.hashPassword(password));
        expectTypedError(error, e.expected.error, e.expected.reason);
        // SPEC §5 I5：hash 與 verify 套用相同輸入規則
        const verifyError = await captureRejection(
          hasher.verifyPassword(password, vectorEntry("deterministic.json", "det-ascii-default").encoded),
        );
        expectTypedError(verifyError, e.expected.error, e.expected.reason);
      }
    });
  }
});
