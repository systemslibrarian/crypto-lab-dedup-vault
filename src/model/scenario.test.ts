import { describe, expect, it } from "vitest";

import { equalBytes, utf8, type ByteRng } from "../crypto/bytes";
import { VoprfKeyServer } from "../crypto/voprf";
import { retrieveUpload, runComparison } from "./scenario";

function sequenceRng(): ByteRng {
  let call = 0;
  return (length) => {
    call += 1;
    return Uint8Array.from(
      { length },
      (_, index) => (call * 31 + index) & 0xff,
    );
  };
}

describe("two-user mode comparison", () => {
  it("(DV-01) computes actual equality and storage for fresh, local MLE, and server-aided modes", () => {
    const file = utf8("Synthetic transcript: exam result = pass.");
    const server = new VoprfKeyServer({
      limit: 8,
      authorized: ["alice", "bob", "mallory"],
      seed: new Uint8Array(32).fill(0x33),
    });
    const evidence = runComparison(file, { rng: sequenceRng(), server });

    const fresh = evidence.modes.fresh;
    expect(fresh.equalDataCiphertexts).toBe(false);
    expect(fresh.uniqueBlobs).toBe(2);
    expect(fresh.uniqueDataBytes).toBe(file.length * 2);
    expect(fresh.dataDedupRatio).toBe(1);

    for (const mode of ["local-mle", "server-aided"] as const) {
      const result = evidence.modes[mode];
      expect(result.equalDataCiphertexts).toBe(true);
      expect(result.distinctCapsules).toBe(true);
      expect(result.uniqueBlobs).toBe(1);
      expect(result.references).toBe(2);
      expect(result.uniqueDataBytes).toBe(file.length);
      expect(result.capsuleBytes).toBe(64);
      expect(result.totalStoredBytes).toBe(file.length + 64);
      expect(result.dataDedupRatio).toBe(2);
      expect(result.uploads[1].deduplicated).toBe(true);
    }

    const serverUploads = evidence.modes["server-aided"].uploads;
    expect(serverUploads[0].voprf?.blinded).not.toEqual(
      serverUploads[1].voprf?.blinded,
    );
    expect(serverUploads[0].voprf?.output).toEqual(
      serverUploads[1].voprf?.output,
    );
    expect(serverUploads[0].dataKey).toEqual(serverUploads[1].dataKey);
  });

  it("retrieves each mode by authenticating its user capsule before CTR decryption", () => {
    const file = utf8("retrieval target");
    const evidence = runComparison(file, { rng: sequenceRng() });
    for (const mode of Object.values(evidence.modes)) {
      for (const upload of mode.uploads)
        expect(retrieveUpload(upload)).toEqual(file);
    }
  });

  it("draws distinct user wrapping keys and does not mutate caller file bytes", () => {
    const file = utf8("immutable input");
    const original = file.slice();
    const evidence = runComparison(file, { rng: sequenceRng() });
    expect(file).toEqual(original);
    const local = evidence.modes["local-mle"].uploads;
    expect(equalBytes(local[0].userWrapKey, local[1].userWrapKey)).toBe(false);
  });

  it("rejects an empty comparison file and unexpected key-server refusal", () => {
    expect(() => runComparison(new Uint8Array())).toThrow(/must not be empty/);
    const server = new VoprfKeyServer({
      limit: 1,
      authorized: ["alice"],
      seed: new Uint8Array(32),
    });
    expect(() =>
      runComparison(utf8("x"), { rng: sequenceRng(), server }),
    ).toThrow(/unexpected key-server refusal/);
  });
});
