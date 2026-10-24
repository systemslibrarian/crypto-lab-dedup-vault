import { describe, expect, it } from "vitest";

import {
  bytesToHex,
  decodeUtf8,
  domainHash,
  equalBytes,
  flipByte,
  hexToBytes,
  randomBytes,
  utf8,
} from "./bytes";

describe("byte helpers", () => {
  it("round-trips UTF-8 and hexadecimal bytes", () => {
    const bytes = utf8("Dedup vault — α");
    expect(decodeUtf8(bytes)).toBe("Dedup vault — α");
    expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes);
  });

  it("rejects malformed hexadecimal input", () => {
    expect(() => hexToBytes("abc")).toThrow(/complete hexadecimal bytes/);
    expect(() => hexToBytes("zz")).toThrow(/complete hexadecimal bytes/);
  });

  it("uses length-framed domain hashing", () => {
    expect(domainHash("x", utf8("ab"), utf8("c"))).not.toEqual(
      domainHash("x", utf8("a"), utf8("bc")),
    );
    expect(domainHash("x", utf8("same"))).not.toEqual(
      domainHash("y", utf8("same")),
    );
  });

  it("compares complete arrays and flips only the selected byte", () => {
    const original = hexToBytes("001122");
    expect(equalBytes(original, hexToBytes("001122"))).toBe(true);
    expect(equalBytes(original, hexToBytes("001123"))).toBe(false);
    expect(equalBytes(original, hexToBytes("0011"))).toBe(false);
    expect(bytesToHex(flipByte(original, 1))).toBe("001022");
    expect(bytesToHex(original)).toBe("001122");
    expect(() => flipByte(original, 3)).toThrow(/out of range/);
  });

  it("draws the requested random bytes and rejects invalid lengths", () => {
    expect(randomBytes(17)).toHaveLength(17);
    expect(() => randomBytes(0)).toThrow(/positive integer/);
    expect(() => randomBytes(1.5)).toThrow(/positive integer/);
  });
});
