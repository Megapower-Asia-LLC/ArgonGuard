import { describe, expect, it } from "vitest";
import type { PhcHash } from "../src/phc.js";
import { checkPolicy } from "../src/policy.js";
import { ReasonCodes } from "../src/reasonCodes.js";

/** 驗證政策單元測試（SPEC §4）：每一維度 reason code＋裁決順序（baseline §3）。 */

function hash(overrides: Partial<{
  version: number | null;
  m: number;
  t: number;
  p: number;
  saltLen: number;
  tagLen: number;
  hasKeyid: boolean;
  hasData: boolean;
}> = {}): PhcHash {
  const o = {
    version: 19 as number | null,
    m: 19456,
    t: 2,
    p: 1,
    saltLen: 16,
    tagLen: 32,
    hasKeyid: false,
    hasData: false,
    ...overrides,
  };
  return {
    algorithm: "argon2id",
    version: o.version,
    m: o.m,
    t: o.t,
    p: o.p,
    salt: Buffer.alloc(o.saltLen),
    tag: Buffer.alloc(o.tagLen),
    hasKeyid: o.hasKeyid,
    hasData: o.hasData,
  };
}

describe("政策各維度 reason code", () => {
  it("in-policy → null", () => expect(checkPolicy(hash())).toBeNull());

  it("missing_version", () => expect(checkPolicy(hash({ version: null }))).toBe(ReasonCodes.MissingVersion));
  it("unsupported_version (v=16)", () => expect(checkPolicy(hash({ version: 16 }))).toBe(ReasonCodes.UnsupportedVersion));
  it("keyid_not_allowed", () => expect(checkPolicy(hash({ hasKeyid: true }))).toBe(ReasonCodes.KeyidNotAllowed));
  it("data_not_allowed", () => expect(checkPolicy(hash({ hasData: true }))).toBe(ReasonCodes.DataNotAllowed));
  it("p_not_one (p=2)", () => expect(checkPolicy(hash({ p: 2 }))).toBe(ReasonCodes.PNotOne));
  it("p_not_one (p=0)", () => expect(checkPolicy(hash({ p: 0 }))).toBe(ReasonCodes.PNotOne));
  it("t_above_ceiling (t=9)", () => expect(checkPolicy(hash({ t: 9, m: 7168 }))).toBe(ReasonCodes.TAboveCeiling));
  it("m_above_ceiling (m=262145)", () => expect(checkPolicy(hash({ m: 262145 }))).toBe(ReasonCodes.MAboveCeiling));
  it("below_owasp_frontier (t=0)", () => expect(checkPolicy(hash({ t: 0 }))).toBe(ReasonCodes.BelowOwaspFrontier));
  it("salt_length_out_of_range (15)", () => expect(checkPolicy(hash({ saltLen: 15 }))).toBe(ReasonCodes.SaltLengthOutOfRange));
  it("salt_length_out_of_range (65)", () => expect(checkPolicy(hash({ saltLen: 65 }))).toBe(ReasonCodes.SaltLengthOutOfRange));
  it("tag_length_out_of_range (31)", () => expect(checkPolicy(hash({ tagLen: 31 }))).toBe(ReasonCodes.TagLengthOutOfRange));
  it("tag_length_out_of_range (129)", () => expect(checkPolicy(hash({ tagLen: 129 }))).toBe(ReasonCodes.TagLengthOutOfRange));
});

describe("OWASP frontier 凍結表逐列邊界（engine-units.json）", () => {
  const frontier: [number, number][] = [
    [1, 47104],
    [2, 19456],
    [3, 12288],
    [4, 9216],
    [5, 7168],
  ];
  for (const [t, minM] of frontier) {
    it(`t=${t}: m=${minM} 過、m=${minM - 1} 拒`, () => {
      expect(checkPolicy(hash({ t, m: minM }))).toBeNull();
      expect(checkPolicy(hash({ t, m: minM - 1 }))).toBe(ReasonCodes.BelowOwaspFrontier);
    });
  }

  it("t=6/7/8 沿用 t>=5 地板 7168", () => {
    for (const t of [6, 7, 8]) {
      expect(checkPolicy(hash({ t, m: 7168 }))).toBeNull();
      expect(checkPolicy(hash({ t, m: 7167 }))).toBe(ReasonCodes.BelowOwaspFrontier);
    }
  });
});

describe("天花板邊界", () => {
  it("m=262144 過、262145 拒", () => {
    expect(checkPolicy(hash({ m: 262144 }))).toBeNull();
    expect(checkPolicy(hash({ m: 262145 }))).toBe(ReasonCodes.MAboveCeiling);
  });
  it("t=8 過、t=9 拒", () => {
    expect(checkPolicy(hash({ t: 8, m: 7168 }))).toBeNull();
    expect(checkPolicy(hash({ t: 9, m: 7168 }))).toBe(ReasonCodes.TAboveCeiling);
  });
  it("salt [16,64]、tag [32,128] 邊界過", () => {
    expect(checkPolicy(hash({ saltLen: 16 }))).toBeNull();
    expect(checkPolicy(hash({ saltLen: 64 }))).toBeNull();
    expect(checkPolicy(hash({ tagLen: 32 }))).toBeNull();
    expect(checkPolicy(hash({ tagLen: 128 }))).toBeNull();
  });
});

describe("多重違規時回報第一個命中者（baseline §3 裁決順序）", () => {
  it("missing_version 先於 p_not_one", () => {
    expect(checkPolicy(hash({ version: null, p: 2 }))).toBe(ReasonCodes.MissingVersion);
  });
  it("unsupported_version 先於 keyid", () => {
    expect(checkPolicy(hash({ version: 16, hasKeyid: true }))).toBe(ReasonCodes.UnsupportedVersion);
  });
  it("keyid 先於 data", () => {
    expect(checkPolicy(hash({ hasKeyid: true, hasData: true }))).toBe(ReasonCodes.KeyidNotAllowed);
  });
  it("p_not_one 先於 t_above_ceiling", () => {
    expect(checkPolicy(hash({ p: 2, t: 9 }))).toBe(ReasonCodes.PNotOne);
  });
  it("t_above_ceiling 先於 m_above_ceiling", () => {
    expect(checkPolicy(hash({ t: 9, m: 262145 }))).toBe(ReasonCodes.TAboveCeiling);
  });
  it("m_above_ceiling 先於 salt 範圍", () => {
    expect(checkPolicy(hash({ m: 262145, saltLen: 8 }))).toBe(ReasonCodes.MAboveCeiling);
  });
  it("frontier 先於 salt 範圍", () => {
    expect(checkPolicy(hash({ m: 7167, t: 5, saltLen: 8 }))).toBe(ReasonCodes.BelowOwaspFrontier);
  });
  it("salt 範圍先於 tag 範圍", () => {
    expect(checkPolicy(hash({ saltLen: 8, tagLen: 16 }))).toBe(ReasonCodes.SaltLengthOutOfRange);
  });
});
