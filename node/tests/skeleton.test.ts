import { describe, expect, it } from "vitest";
import { SPEC_VERSION } from "../src/index.js";

describe("skeleton", () => {
  it("SPEC_VERSION is defined", () => {
    expect(SPEC_VERSION.length).toBeGreaterThan(0);
  });
});
