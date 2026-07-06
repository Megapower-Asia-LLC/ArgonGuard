import { describe, expect, it } from "vitest";
import { MalformedHashError } from "../src/errors.js";
import { encodePhc, parsePhc, tryGetAlgorithm } from "../src/phc.js";
import { ReasonCodes } from "../src/reasonCodes.js";

/** PHC 嚴格 parser／encoder 單元測試（SPEC §2、§4 S1–S4；baseline §1/§4）。 */

const VALID = "$argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE";

function reasonOf(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(MalformedHashError);
    return (error as MalformedHashError).reason;
  }
  throw new Error("expected MalformedHashError");
}

describe("tryGetAlgorithm (dispatch 前置 token 判斷, baseline §1)", () => {
  it("argon2id token", () => expect(tryGetAlgorithm(VALID)).toBe("argon2id"));
  it("argon2i token", () => expect(tryGetAlgorithm("$argon2i$v=19$x")).toBe("argon2i"));
  it("bcrypt 2b token", () => expect(tryGetAlgorithm("$2b$12$abc")).toBe("2b"));
  it("token 可含 dash", () => expect(tryGetAlgorithm("$scrypt-x$rest")).toBe("scrypt-x"));
  it("非 $ 開頭 → null", () => expect(tryGetAlgorithm("argon2id$v=19")).toBeNull());
  it("空字串 → null", () => expect(tryGetAlgorithm("")).toBeNull());
  it("空 token（$$）→ null", () => expect(tryGetAlgorithm("$$rest")).toBeNull());
  it("無第二個 $ → null", () => expect(tryGetAlgorithm("$argon2id")).toBeNull());
  it("token 含大寫 → null", () => expect(tryGetAlgorithm("$Argon2id$rest")).toBeNull());
  it("token 含底線 → null", () => expect(tryGetAlgorithm("$argon_2$rest")).toBeNull());
});

describe("parsePhc 合法路徑", () => {
  it("完整欄位解析", () => {
    const h = parsePhc(VALID);
    expect(h.algorithm).toBe("argon2id");
    expect(h.version).toBe(19);
    expect(h.m).toBe(19456);
    expect(h.t).toBe(2);
    expect(h.p).toBe(1);
    expect(Buffer.from(h.salt).toString("utf8")).toBe("AronGuardV1S01!!");
    expect(h.tag.length).toBe(32);
    expect(h.hasKeyid).toBe(false);
    expect(h.hasData).toBe(false);
  });

  it("缺 v 段可解析（missing_version 屬政策層裁決）", () => {
    const h = parsePhc("$argon2id$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE");
    expect(h.version).toBeNull();
    expect(h.m).toBe(19456);
  });

  it("keyid/data 旗標可解析（政策層拒絕）", () => {
    const withKeyid = parsePhc("$argon2id$v=19$m=19456,t=2,p=1,keyid=Zm9v$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE");
    expect(withKeyid.hasKeyid).toBe(true);
    const withData = parsePhc("$argon2id$v=19$m=19456,t=2,p=1,data=Zm9v$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE");
    expect(withData.hasData).toBe(true);
  });

  it("m=0 可解析（單獨 0 不算前導零）", () => {
    expect(parsePhc("$argon2id$v=19$m=0,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE").m).toBe(0);
  });

  it("15 位數字可解析（防溢位上限內）", () => {
    expect(parsePhc("$argon2id$v=19$m=999999999999999,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE").m).toBe(999_999_999_999_999);
  });
});

describe("parsePhc 非法路徑 → not_phc", () => {
  const cases: [string, string][] = [
    ["空字串", ""],
    ["垃圾字串", "not-a-hash-at-all"],
    ["段數不足", "$argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ"],
    ["段數過多", "$argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE$extra"],
    ["演算法 token 含大寫", "$Argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
    ["空演算法 token", "$$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
    ["v 段格式錯誤", "$argon2id$version=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
    ["v 值非數字", "$argon2id$v=x9$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
    ["params 少於三個", "$argon2id$v=19$m=19456,t=2$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
    ["m 值前導零", "$argon2id$v=19$m=019456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
    ["m 值超過 15 位", "$argon2id$v=19$m=1234567890123456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
    ["m 值含非數字", "$argon2id$v=19$m=19x56,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
    ["m 值帶正號", "$argon2id$v=19$m=+19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
    ["m 值為空", "$argon2id$v=19$m=,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
    ["第 4 個 param 非 keyid/data", "$argon2id$v=19$m=19456,t=2,p=1,x=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
    ["前三 token 含未知名（非重排）", "$argon2id$v=19$m=19456,x=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
  ];
  for (const [name, encoded] of cases) {
    it(name, () => expect(reasonOf(() => parsePhc(encoded))).toBe(ReasonCodes.NotPhc));
  }
});

describe("parsePhc 非法路徑 → params_out_of_order", () => {
  const cases: [string, string][] = [
    ["t,m,p", "$argon2id$v=19$t=2,m=19456,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
    ["p,t,m", "$argon2id$v=19$p=1,t=2,m=19456$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
    ["m,p,t", "$argon2id$v=19$m=19456,p=1,t=2$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
  ];
  for (const [name, encoded] of cases) {
    it(name, () => expect(reasonOf(() => parsePhc(encoded))).toBe(ReasonCodes.ParamsOutOfOrder));
  }
});

describe("parsePhc 非法路徑 → bad_base64", () => {
  const cases: [string, string][] = [
    ["salt 帶 padding", "$argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ==$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
    ["tag base64url 字元", "$argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$-_ERERERERERERERERERERERERERERERERERERERERE"],
    ["salt 空字串", "$argon2id$v=19$m=19456,t=2,p=1$$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
    ["salt 長度 mod 4 == 1", "$argon2id$v=19$m=19456,t=2,p=1$QXJvb$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
    // "QQF" decode 後 re-encode 為 "QQE"（trailing bits 非零）→ 非 canonical
    ["非 canonical（trailing-bit 可鍛性）", "$argon2id$v=19$m=19456,t=2,p=1$QQF$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
    ["含空白", "$argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEh IQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"],
  ];
  for (const [name, encoded] of cases) {
    it(name, () => expect(reasonOf(() => parsePhc(encoded))).toBe(ReasonCodes.BadBase64));
  }
});

describe("encodePhc (SPEC §2 G1–G8)", () => {
  it("輸出標準 PHC 格式（v 明示、m,t,p 依序、無 padding base64）", () => {
    const salt = Buffer.from("AronGuardV1S01!!", "utf8");
    const tag = Buffer.from("IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE", "base64");
    expect(encodePhc(19456, 2, 1, salt, tag)).toBe(VALID);
  });

  it("encode → parse 往返一致", () => {
    const salt = Buffer.alloc(16, 0xab);
    const tag = Buffer.alloc(32, 0xcd);
    const encoded = encodePhc(65536, 2, 1, salt, tag);
    const parsed = parsePhc(encoded);
    expect(parsed.m).toBe(65536);
    expect(Buffer.compare(Buffer.from(parsed.salt), salt)).toBe(0);
    expect(Buffer.compare(Buffer.from(parsed.tag), tag)).toBe(0);
  });
});
