import { sha256 } from "@noble/hashes/sha2.js";
import { aessiv, ctr } from "@noble/ciphers/aes.js";
import { describe, expect, it } from "vitest";

import {
  capsuleAssociatedData,
  capsuleStorageBytes,
  decryptData,
  deriveLocalDataKey,
  deriveVoprfInput,
  encryptData,
  freshDataKey,
  freshUserWrapKey,
  localDerivationTranscript,
  openDataKeyCapsule,
  publicParameter,
  wrapDataKey,
} from "./aes";
import { bytesToHex, concatBytes, flipByte, hexToBytes, utf8 } from "./bytes";

describe("AES data encryption and key capsules", () => {
  it("matches NIST SP 800-38A F.5 AES-128-CTR", () => {
    const key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
    const counter = hexToBytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    const plaintext = hexToBytes(
      "6bc1bee22e409f96e93d7e117393172a" +
        "ae2d8a571e03ac9c9eb76fac45af8e51" +
        "30c81c46a35ce411e5fbc1191a0a52ef" +
        "f69f2445df4f9b17ad2b417be66c3710",
    );
    const expected =
      "874d6191b620e3261bef6864990db6ce" +
      "9806f66b7970fdff8617187bb9fffdff" +
      "5ae4df3edbd5d35e5b4f09020db03eab" +
      "1e031dda2fbe03d1792170a0f3009cee";

    const ciphertext = ctr(key, counter).encrypt(plaintext);
    expect(bytesToHex(ciphertext)).toBe(expected);
    expect(ctr(key, counter).decrypt(ciphertext)).toEqual(plaintext);

    const teachingCiphertext = encryptData(key, plaintext);
    expect(decryptData(key, teachingCiphertext)).toEqual(plaintext);
  });

  it("matches RFC 5297 Appendix A.1 AES-SIV", () => {
    const key = hexToBytes(
      "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0" + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    );
    const associated = hexToBytes(
      "101112131415161718191a1b1c1d1e1f2021222324252627",
    );
    const plaintext = hexToBytes("112233445566778899aabbccddee");
    const expected = hexToBytes(
      "85632d07c6e8f37f950acd320a2ecc93" + "40c02b9690c4dc04daef7f6afe5c",
    );
    const owner = "test-owner";
    const reference = "test-reference";
    const dataCiphertext = utf8("test-data-ciphertext");

    // Directly exercise the same primitive with the RFC's single AD component.
    expect(aessiv(key, associated).encrypt(plaintext)).toEqual(expected);

    const dataKey = hexToBytes("00112233445566778899aabbccddeeff");
    const capsule = wrapDataKey(key, dataKey, owner, reference, dataCiphertext);
    expect(
      openDataKeyCapsule(key, capsule, owner, reference, dataCiphertext),
    ).toEqual(dataKey);
  });

  it("matches RFC 5297 Appendix A.2 nonce-based AES-SIV", () => {
    const key = hexToBytes(
      "7f7e7d7c7b7a79787776757473727170" + "404142434445464748494a4b4c4d4e4f",
    );
    const associated1 = hexToBytes(
      "00112233445566778899aabbccddeeff" +
        "deaddadadeaddadaffeeddccbbaa9988" +
        "7766554433221100",
    );
    const associated2 = hexToBytes("102030405060708090a0");
    const nonce = hexToBytes("09f911029d74e35bd84156c5635688c0");
    const plaintext = hexToBytes(
      "7468697320697320736f6d6520706c61" +
        "696e7465787420746f20656e63727970" +
        "74207573696e67205349562d414553",
    );
    const expected = hexToBytes(
      "7bdb6e3b432667eb06f4d14bff2fbd0f" +
        "cb900f2fddbe404326601965c889bf17" +
        "dba77ceb094fa663b7a3f748ba8af829" +
        "ea64ad544a272e9c485b62a3fd5c0d",
    );

    const ciphertext = aessiv(key, associated1, associated2, nonce).encrypt(
      plaintext,
    );
    expect(ciphertext).toEqual(expected);
    expect(
      aessiv(key, associated1, associated2, nonce).decrypt(ciphertext),
    ).toEqual(plaintext);
  });

  it("(DV-15 DV-19) authenticates scheme, owner, reference, complete data ciphertext, capsule, and wrapping key", () => {
    const userKey = Uint8Array.from({ length: 32 }, (_, index) => index);
    const dataKey = Uint8Array.from({ length: 16 }, (_, index) => 0xa0 + index);
    const ciphertext = utf8("encrypted file bytes");
    const capsule = wrapDataKey(
      userKey,
      dataKey,
      "alice",
      "report",
      ciphertext,
    );

    expect(
      openDataKeyCapsule(userKey, capsule, "alice", "report", ciphertext),
    ).toEqual(dataKey);
    expect(() =>
      openDataKeyCapsule(userKey, capsule, "bob", "report", ciphertext),
    ).toThrow();
    expect(() =>
      openDataKeyCapsule(userKey, capsule, "alice", "other", ciphertext),
    ).toThrow();
    expect(() =>
      openDataKeyCapsule(
        userKey,
        capsule,
        "alice",
        "report",
        flipByte(ciphertext),
      ),
    ).toThrow();
    const [, ...otherAssociatedData] = capsuleAssociatedData(
      "alice",
      "report",
      ciphertext,
    );
    expect(() =>
      aessiv(
        userKey,
        utf8("dedup-vault/capsule/v2"),
        ...otherAssociatedData,
      ).decrypt(capsule),
    ).toThrow();
    expect(() =>
      openDataKeyCapsule(
        userKey,
        flipByte(capsule),
        "alice",
        "report",
        ciphertext,
      ),
    ).toThrow();
    expect(() =>
      openDataKeyCapsule(
        flipByte(userKey),
        capsule,
        "alice",
        "report",
        ciphertext,
      ),
    ).toThrow();
    expect(capsuleAssociatedData("alice", "report", ciphertext)).toHaveLength(
      4,
    );
  });

  it("(DV-02) derives local MLE exactly as first128(SHA-256(P || M))", () => {
    const file = utf8("same synthetic file");
    expect(deriveLocalDataKey(file)).toEqual(
      sha256(concatBytes(publicParameter(), file)).slice(0, 16),
    );
    expect(deriveLocalDataKey(file)).toEqual(deriveLocalDataKey(file));
    expect(deriveLocalDataKey(file)).not.toEqual(
      deriveLocalDataKey(utf8("different file")),
    );
    expect(deriveVoprfInput(file)).toHaveLength(32);
    expect(localDerivationTranscript(file)).toEqual(
      concatBytes(publicParameter(), file),
    );
    const exposedParameter = publicParameter();
    exposedParameter.fill(0);
    expect(publicParameter()).not.toEqual(exposedParameter);
    expect(() => deriveLocalDataKey(new Uint8Array())).toThrow(/non-empty/);
    expect(() => deriveVoprfInput(new Uint8Array())).toThrow(/non-empty/);
  });

  it("validates key, file, and RNG lengths", () => {
    expect(() => encryptData(new Uint8Array(15), utf8("x"))).toThrow(
      /16 bytes/,
    );
    expect(() => encryptData(new Uint8Array(16), new Uint8Array())).toThrow(
      /non-empty/,
    );
    expect(() => decryptData(new Uint8Array(16), new Uint8Array())).toThrow(
      /must not be empty/,
    );
    expect(() => freshDataKey(() => new Uint8Array(15))).toThrow(/16 bytes/);
    expect(() => freshUserWrapKey(() => new Uint8Array(31))).toThrow(
      /32 bytes/,
    );
    expect(() =>
      wrapDataKey(new Uint8Array(31), new Uint8Array(16), "a", "r", utf8("c")),
    ).toThrow(/32 bytes/);
    expect(() =>
      wrapDataKey(new Uint8Array(32), new Uint8Array(15), "a", "r", utf8("c")),
    ).toThrow(/16 bytes/);
    expect(() => capsuleAssociatedData("", "r", utf8("c"))).toThrow(
      /non-empty owner/,
    );
    expect(() => capsuleAssociatedData("a", "r", new Uint8Array())).toThrow(
      /ciphertext/,
    );
    expect(() => capsuleAssociatedData("\ud800", "r", utf8("c"))).toThrow(
      /well-formed Unicode/,
    );
    expect(() => capsuleAssociatedData("a", "\udc00", utf8("c"))).toThrow(
      /well-formed Unicode/,
    );
    expect(() =>
      capsuleAssociatedData("alice-🗝️", "报告", utf8("c")),
    ).not.toThrow();
    expect(capsuleStorageBytes([new Uint8Array(32), new Uint8Array(48)])).toBe(
      80,
    );
  });
});
