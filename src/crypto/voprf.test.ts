import { p256_oprf } from "@noble/curves/nist.js";
import { describe, expect, it } from "vitest";

import { bytesToHex, equalBytes, flipByte, hexToBytes, utf8 } from "./bytes";
import {
  deriveServerDataKey,
  finalizeVoprfTranscript,
  voprfKeyInfo,
  VoprfKeyServer,
} from "./voprf";

const RFC_SEED = hexToBytes("a3".repeat(32));
const RFC_SK =
  "ca5d94c8807817669a51b196c34c1b7f8442fde4334a7121ae4736364312fca6";
const RFC_PK =
  "03e17e70604bcabe198882c0a1f27a92441e774224ed9c702e51dd17038b102462";
const RFC_BLIND =
  "3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364";
const RFC_BLINDED =
  "02dd05901038bb31a6fae01828fd8d0e49e35a486b5c5d4b4994013648c01277da";
const RFC_EVALUATED =
  "0209f33cab60cf8fe69239b0afbcfcd261af4c1c5632624f2e9ba29b90ae83e4a2";
const RFC_PROOF =
  "e7c2b3c5c954c035949f1f74e6bce2ed539a3be267d1481e9ddb178533df4c26" +
  "64f69d065c604a4fd953e100b856ad83804eb3845189babfa5a702090d6fc5fa";
const RFC_OUTPUT =
  "0412e8f78b02c415ab3a288e228978376f99927767ff37c5718d420010a645a1";

function derive(
  file: Uint8Array,
  server: VoprfKeyServer,
  identity: string,
  blindRng?: (length: number) => Uint8Array,
  proofRng?: (length: number) => Uint8Array,
) {
  return deriveServerDataKey(
    file,
    server,
    identity,
    server.publicKey(),
    blindRng,
    proofRng,
  );
}

describe("RFC 9497 P256-SHA256 VOPRF", () => {
  it("matches Appendix A.3.2.1 key derivation, proof verification, and output", () => {
    const keys = p256_oprf.voprf.deriveKeyPair(
      RFC_SEED,
      hexToBytes("74657374206b6579"),
    );
    expect(bytesToHex(keys.secretKey)).toBe(RFC_SK);
    expect(bytesToHex(keys.publicKey)).toBe(RFC_PK);

    const output = p256_oprf.voprf.finalize(
      hexToBytes("00"),
      hexToBytes(RFC_BLIND),
      hexToBytes(RFC_EVALUATED),
      hexToBytes(RFC_BLINDED),
      keys.publicKey,
      hexToBytes(RFC_PROOF),
    );
    expect(bytesToHex(output)).toBe(RFC_OUTPUT);

    const evaluated = p256_oprf.voprf.blindEvaluate(
      keys.secretKey,
      keys.publicKey,
      hexToBytes(RFC_BLINDED),
    );
    expect(bytesToHex(evaluated.evaluated)).toBe(RFC_EVALUATED);
    expect(
      bytesToHex(
        p256_oprf.voprf.finalize(
          hexToBytes("00"),
          hexToBytes(RFC_BLIND),
          evaluated.evaluated,
          hexToBytes(RFC_BLINDED),
          keys.publicKey,
          evaluated.proof,
        ),
      ),
    ).toBe(RFC_OUTPUT);
  });

  it("uses fresh blinds while producing the same verified output", () => {
    const server = new VoprfKeyServer({
      limit: 4,
      authorized: ["alice"],
      seed: RFC_SEED,
    });
    const file = utf8("same synthetic file");
    const first = derive(file, server, "alice");
    const second = derive(file, server, "alice");
    expect(first.status).toBe("ok");
    expect(second.status).toBe("ok");
    if (first.status !== "ok" || second.status !== "ok")
      throw new Error("unreachable");
    expect(first.transcript.blinded).not.toEqual(second.transcript.blinded);
    expect(first.transcript.output).toEqual(second.transcript.output);
    expect(finalizeVoprfTranscript(first.transcript)).toEqual(
      first.transcript.output,
    );
  });

  it("accepts injected ArrayBufferLike RNG output without retaining it", () => {
    const server = new VoprfKeyServer({
      limit: 1,
      authorized: ["alice"],
      seed: RFC_SEED,
    });
    const sources: Uint8Array[] = [];
    const sharedRng = (fill: number) => (length: number) => {
      const source = new Uint8Array(new SharedArrayBuffer(length)).fill(fill);
      sources.push(source);
      return source;
    };
    const result = derive(
      utf8("deterministic transcript"),
      server,
      "alice",
      sharedRng(0x07),
      sharedRng(0x09),
    );

    expect(result.status).toBe("ok");
    if (result.status !== "ok") throw new Error("unreachable");
    for (const source of sources) source.fill(0xff);
    expect(finalizeVoprfTranscript(result.transcript)).toEqual(
      result.transcript.output,
    );
  });

  it("(DV-03 DV-16) rejects tampering and a coherent response under an unpinned public key", () => {
    const server = new VoprfKeyServer({
      limit: 3,
      authorized: ["alice"],
      seed: RFC_SEED,
    });
    const result = derive(utf8("proof target"), server, "alice");
    expect(result.status).toBe("ok");
    if (result.status !== "ok") throw new Error("unreachable");
    expect(() =>
      finalizeVoprfTranscript(
        result.transcript,
        flipByte(result.transcript.proof),
      ),
    ).toThrow(/proof verification failed/);
    expect(() =>
      p256_oprf.voprf.finalize(
        result.transcript.input,
        result.transcript.blind,
        flipByte(result.transcript.evaluated),
        result.transcript.blinded,
        result.transcript.publicKey,
        result.transcript.proof,
      ),
    ).toThrow();
    const other = new VoprfKeyServer({ limit: 1, authorized: ["alice"] });
    expect(() =>
      p256_oprf.voprf.finalize(
        result.transcript.input,
        result.transcript.blind,
        result.transcript.evaluated,
        result.transcript.blinded,
        other.publicKey(),
        result.transcript.proof,
      ),
    ).toThrow();

    const substitute = new VoprfKeyServer({
      limit: 1,
      authorized: ["alice"],
      seed: new Uint8Array(32).fill(0x55),
    });
    expect(() =>
      deriveServerDataKey(
        utf8("coherent substitute"),
        substitute,
        "alice",
        server.publicKey(),
      ),
    ).toThrow(/proof verification failed/);
  });

  it("(DV-04 DV-05) checks the modeled allowlist before counting and enforces exactly q requests per principal", () => {
    const server = new VoprfKeyServer({
      limit: 2,
      authorized: ["alice"],
      seed: RFC_SEED,
    });
    const file = utf8("budgeted input");
    const denied = derive(file, server, "eve");
    expect(denied.status).toBe("principal-rejected");
    expect(server.count("eve")).toBe(0);
    expect(derive(file, server, "alice").status).toBe("ok");
    expect(derive(file, server, "alice").status).toBe("ok");
    const limited = derive(file, server, "alice");
    expect(limited.status).toBe("rate-limited");
    expect(server.count("alice")).toBe(2);
  });

  it("keeps identities separate, honors revocation, and changes output on rotation", () => {
    const server = new VoprfKeyServer({
      limit: 1,
      authorized: ["alice", "bob"],
      seed: RFC_SEED,
    });
    const file = utf8("rotation input");
    const alice = derive(file, server, "alice");
    const bob = derive(file, server, "bob");
    expect(alice.status).toBe("ok");
    expect(bob.status).toBe("ok");
    if (alice.status !== "ok") throw new Error("unreachable");
    expect(derive(file, server, "alice").status).toBe("rate-limited");

    server.revoke("bob");
    server.rotate(new Uint8Array(32).fill(0x55));
    expect(derive(file, server, "bob").status).toBe("principal-rejected");
    server.authorize("bob");
    const rotated = derive(file, server, "bob");
    expect(rotated.status).toBe("ok");
    if (rotated.status !== "ok") throw new Error("unreachable");
    expect(equalBytes(alice.transcript.output, rotated.transcript.output)).toBe(
      false,
    );
    expect(server.epoch).toBe(2);
  });

  it("(DV-13) advances a rate epoch without changing the VOPRF key or deterministic output", () => {
    const server = new VoprfKeyServer({
      limit: 1,
      authorized: ["alice"],
      seed: RFC_SEED,
    });
    const file = utf8("same file across rate windows");
    const first = derive(file, server, "alice");
    expect(first.status).toBe("ok");
    expect(derive(file, server, "alice").status).toBe("rate-limited");
    const publicKey = server.publicKey();

    server.advanceEpoch();
    const next = derive(file, server, "alice");
    expect(next.status).toBe("ok");
    if (first.status !== "ok" || next.status !== "ok")
      throw new Error("unreachable");
    expect(next.transcript.output).toEqual(first.transcript.output);
    expect(server.publicKey()).toEqual(publicKey);
    expect(next.transcript.epoch).toBe(2);
  });

  it("validates limit and keeps the application key-info label stable", () => {
    expect(() => new VoprfKeyServer({ limit: 0 })).toThrow(/positive integer/);
    expect(() => new VoprfKeyServer({ limit: 1.5 })).toThrow(
      /positive integer/,
    );
    const exposedKeyInfo = voprfKeyInfo();
    expect(new TextDecoder().decode(exposedKeyInfo)).toBe(
      "dedup-vault/v1/key-server",
    );
    exposedKeyInfo.fill(0);
    expect(new TextDecoder().decode(voprfKeyInfo())).toBe(
      "dedup-vault/v1/key-server",
    );
  });
});
