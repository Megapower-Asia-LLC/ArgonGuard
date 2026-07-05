import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  ArgonGuardPasswordHasher,
  InvalidInputError,
  MalformedHashError,
  PolicyViolationError,
  UnsupportedAlgorithmError,
  SPEC_VERSION,
  type LegacyPasswordVerifier,
} from "../src/index.js";

/**
 * README 範例的可執行版本（文件與 CI 同源、防腐化）。
 * 這裡的程式碼即 node/README.md 各節貼出的程式碼；import 位置改用 ../src/index.js，
 * 發佈後實際使用是 `import { ArgonGuardPasswordHasher } from "@argonguard/passwords"`。
 */

describe("Quickstart：最小登入流程（hash → verify → needsRehash 升級）", () => {
  it("註冊 → 登入 → default 檔位無需 rehash", async () => {
    const hasher = new ArgonGuardPasswordHasher(); // 預設 default 檔位
    const password = "correct horse battery staple";

    // 註冊時：產生 PHC 字串存進資料庫（每筆獨立 16-byte CSPRNG salt）
    const stored = await hasher.hashPassword(password);
    expect(stored).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);

    // 登入時：務必 await（見 Security Notes）
    const ok = await hasher.verifyPassword(password, stored);
    expect(ok).toBe(true);

    // 已是 active 檔位 → 不需升級
    expect(hasher.needsRehash(stored)).toBe(false);
  });

  it("密碼錯誤 → verify 回 false（不是 throw）", async () => {
    const hasher = new ArgonGuardPasswordHasher();
    const stored = await hasher.hashPassword("right");
    expect(await hasher.verifyPassword("wrong", stored)).toBe(false);
  });

  it("升級分支實跑：舊庫 default、active 提高到 high → needsRehash 觸發 rehash-on-login", async () => {
    // 舊儲存庫以 default 產生
    const oldStored = await new ArgonGuardPasswordHasher({ profile: "default" }).hashPassword("pw");

    // 服務把成本提高到 high
    const hasher = new ArgonGuardPasswordHasher({ profile: "high" });
    const password = "pw";

    let saved = oldStored;
    const save = (h: string): void => {
      saved = h;
    };

    // README quickstart 的登入流程逐字
    if (await hasher.verifyPassword(password, oldStored)) {
      if (hasher.needsRehash(oldStored)) {
        save(await hasher.hashPassword(password)); // 升級成 high
      }
      // loginOk()
    } else {
      throw new Error("verify 應成功");
    }

    expect(saved).not.toBe(oldStored);
    expect(saved).toMatch(/^\$argon2id\$v=19\$m=65536,t=2,p=1\$/);
    expect(hasher.needsRehash(saved)).toBe(false); // 升級後收斂
    expect(await hasher.verifyPassword(password, saved)).toBe(true);
  });
});

describe("Security Notes：忘記 await 的靜默驗證繞過（M5 #7）", () => {
  it("verifyPassword 回 Promise；未 await 的 Promise 恆為 truthy（這就是繞過根因）", async () => {
    const hasher = new ArgonGuardPasswordHasher();
    const stored = await hasher.hashPassword("right");

    // 反例：忘記 await —— p 是 Promise 物件，if (p) 對錯誤密碼也成立
    const p = hasher.verifyPassword("WRONG", stored);
    expect(typeof (p as Promise<boolean>).then).toBe("function"); // 的確是 Promise
    expect(Boolean(p)).toBe(true); // truthy！忘記 await 就會誤放行
    expect(await p).toBe(false); // 正確 await 後才是真正結果

    // 正解：一定要 await
    expect(await hasher.verifyPassword("WRONG", stored)).toBe(false);
  });

  it("needsRehash 是同步（回 boolean，不是 Promise）", async () => {
    const hasher = new ArgonGuardPasswordHasher();
    const stored = await hasher.hashPassword("pw");
    const r = hasher.needsRehash(stored);
    expect(typeof r).toBe("boolean");
  });
});

describe("API 參考：SPEC_VERSION、activeProfile、五 typed error 與 .reason", () => {
  it("SPEC_VERSION 常數", () => {
    expect(SPEC_VERSION).toBe("1.0.0");
  });

  it("activeProfile 反映建構檔位", () => {
    expect(new ArgonGuardPasswordHasher().activeProfile).toBe("default");
    expect(new ArgonGuardPasswordHasher({ profile: "highest" }).activeProfile).toBe("highest");
  });

  it("空密碼 → InvalidInputError（reason=invalid_input.password_empty）", async () => {
    const hasher = new ArgonGuardPasswordHasher();
    await expect(hasher.hashPassword("")).rejects.toMatchObject({
      constructor: InvalidInputError,
      reason: "invalid_input.password_empty",
    });
  });

  it("非 argon2id、無 legacy → UnsupportedAlgorithmError", async () => {
    const hasher = new ArgonGuardPasswordHasher();
    const bcrypt = "$2b$12$LQVkVYq1S7Ck1MQIViYyNOG3Fabe/y0BB6kJ1O8ZQNXY9nCzC1jU6";
    await expect(hasher.verifyPassword("pw", bcrypt)).rejects.toBeInstanceOf(UnsupportedAlgorithmError);
  });

  it("低於 OWASP frontier 的 argon2id → PolicyViolationError", async () => {
    const hasher = new ArgonGuardPasswordHasher();
    const belowFrontier =
      "$argon2id$v=19$m=8,t=1,p=1$QXJvbkd1YXJkVjFTMDEhIQ$ERERERERERERERERERERERERERERERERERERERERERE";
    await expect(hasher.verifyPassword("pw", belowFrontier)).rejects.toMatchObject({
      constructor: PolicyViolationError,
      reason: "policy_violation.below_owasp_frontier",
    });
  });

  it("無法解析的字串 → MalformedHashError", async () => {
    const hasher = new ArgonGuardPasswordHasher();
    await expect(hasher.verifyPassword("pw", "not-a-phc-string")).rejects.toBeInstanceOf(MalformedHashError);
  });
});

/**
 * README §5 舊系統遷移的可執行版本。README 展示 bcryptjs；bcryptjs 非本套件依賴，
 * 此處以 Node 內建 scryptSync 作為「舊雜湊格式」stand-in，證明完全相同的 ArgonGuard 機制：
 * 建構時注入不可變有序 legacy 清單 → 第一個 canHandle 認領者裁決 → legacy 命中 needsRehash 恆 true
 * → 登入成功後 rehash 升級成 argon2id。
 */
describe("舊系統遷移：建構時注入 legacy verifier + 登入後升級（§5 機制）", () => {
  function makeLegacyHash(password: string): string {
    const salt = randomBytes(16);
    const dk = scryptSync(password, salt, 32);
    return `$scrypt$${salt.toString("base64")}$${dk.toString("base64")}`;
  }

  const legacyVerifier: LegacyPasswordVerifier = {
    canHandle: (encoded) => encoded.startsWith("$scrypt$"),
    verify: (password, encoded) => {
      const [, , saltB64, hashB64] = encoded.split("$");
      const salt = Buffer.from(saltB64!, "base64");
      const expected = Buffer.from(hashB64!, "base64");
      const dk = scryptSync(password, salt, expected.length);
      return dk.length === expected.length && timingSafeEqual(dk, expected);
    },
  };

  it("legacy 命中 → 由 legacy 裁決；needsRehash 恆 true；登入成功後升級成 argon2id", async () => {
    const password = "s3cr3t";
    const legacyStored = makeLegacyHash(password);

    const hasher = new ArgonGuardPasswordHasher({
      profile: "default",
      legacyVerifiers: [legacyVerifier],
    });

    // 錯密碼 → false（單一語意仍成立）
    expect(await hasher.verifyPassword("wrong", legacyStored)).toBe(false);

    // 正確密碼 → true，且 legacy 命中的字串 needsRehash 恆 true
    let saved = legacyStored;
    if (await hasher.verifyPassword(password, legacyStored)) {
      expect(hasher.needsRehash(legacyStored)).toBe(true);
      saved = await hasher.hashPassword(password); // 升級成 argon2id
      // loginOk()
    } else {
      throw new Error("legacy 驗證應成功");
    }

    expect(saved).toMatch(/^\$argon2id\$v=19\$/);
    expect(await hasher.verifyPassword(password, saved)).toBe(true); // 走 core path
    expect(hasher.needsRehash(saved)).toBe(false);
  });

  it("runtime 動態註冊不可能：建構後修改原陣列無效（SPEC §6.4 L1）", async () => {
    const list: LegacyPasswordVerifier[] = [];
    const hasher = new ArgonGuardPasswordHasher({ legacyVerifiers: list });
    list.push(legacyVerifier); // 建構後才 push，已凍結複製不受影響
    await expect(hasher.verifyPassword("x", makeLegacyHash("x"))).rejects.toBeInstanceOf(
      UnsupportedAlgorithmError,
    );
  });
});
