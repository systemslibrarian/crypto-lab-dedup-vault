import { describe, expect, it } from "vitest";

import { deriveLocalDataKey, encryptData } from "../crypto/aes";
import { utf8 } from "../crypto/bytes";
import { VoprfKeyServer } from "../crypto/voprf";
import {
  compromisedServerDictionaryAttack,
  offlineDictionaryAttack,
  onlineServerDictionaryAttack,
  type DictionaryCandidate,
} from "./dictionary";

const CANDIDATES: DictionaryCandidate[] = [
  { label: "vacation photo", file: utf8("photo: beach") },
  { label: "negative result", file: utf8("medical result: negative") },
  { label: "positive result", file: utf8("medical result: positive") },
  { label: "tax form", file: utf8("tax form: synthetic") },
];

describe("low-entropy dictionary attacks", () => {
  it("recovers a local MLE target by recomputing and comparing real ciphertexts", () => {
    const target = CANDIDATES[2];
    const ciphertext = encryptData(
      deriveLocalDataKey(target.file),
      target.file,
    );
    const result = offlineDictionaryAttack(ciphertext, CANDIDATES);
    expect(result.outcome).toBe("recovered");
    expect(result.match?.label).toBe("positive result");
    expect(result.attempted).toBe(3);
    expect(result.comparedCiphertexts).toHaveLength(3);
  });

  it("reports a completed dictionary miss without calling the target safe", () => {
    const ciphertext = encryptData(
      deriveLocalDataKey(utf8("not in dictionary")),
      utf8("not in dictionary"),
    );
    const result = offlineDictionaryAttack(ciphertext, CANDIDATES);
    expect(result.outcome).toBe("no-match");
    expect(result.attempted).toBe(4);
    expect(result.note).toMatch(/does not prove high entropy/);
  });

  it("recovers a server-aided target inside q and delays a target beyond q", () => {
    const insideServer = new VoprfKeyServer({
      limit: 3,
      authorized: ["mallory"],
      seed: new Uint8Array(32).fill(0x44),
    });
    const insideTarget = CANDIDATES[2];
    const insideKey = insideServer
      .compromisedEvaluate(insideTarget.file)
      .slice(0, 16);
    const insideCiphertext = encryptData(insideKey, insideTarget.file);
    const inside = onlineServerDictionaryAttack(
      insideCiphertext,
      CANDIDATES,
      insideServer,
      "mallory",
    );
    expect(inside.outcome).toBe("recovered");
    expect(inside.attempted).toBe(3);

    const beyondServer = new VoprfKeyServer({
      limit: 3,
      authorized: ["mallory"],
      seed: new Uint8Array(32).fill(0x55),
    });
    const beyondTarget = CANDIDATES[3];
    const beyondKey = beyondServer
      .compromisedEvaluate(beyondTarget.file)
      .slice(0, 16);
    const beyondCiphertext = encryptData(beyondKey, beyondTarget.file);
    const beyond = onlineServerDictionaryAttack(
      beyondCiphertext,
      CANDIDATES,
      beyondServer,
      "mallory",
    );
    expect(beyond.outcome).toBe("rate-limited");
    expect(beyond.attempted).toBe(3);
    expect(beyond.note).toMatch(/delayed.*not proved impossible/);
  });

  it("rejects a principal outside the modeled allowlist without evaluating a candidate", () => {
    const server = new VoprfKeyServer({
      limit: 3,
      authorized: ["alice"],
      seed: new Uint8Array(32).fill(0x66),
    });
    const result = onlineServerDictionaryAttack(
      utf8("target"),
      CANDIDATES,
      server,
      "eve",
    );
    expect(result.outcome).toBe("principal-rejected");
    expect(result.attempted).toBe(0);
    expect(server.count("eve")).toBe(0);
  });

  it("shows a second identity and key-server compromise as distinct limits", () => {
    const server = new VoprfKeyServer({
      limit: 1,
      authorized: ["mallory", "sybil-2"],
      seed: new Uint8Array(32).fill(0x77),
    });
    const target = CANDIDATES[1];
    const targetKey = server.compromisedEvaluate(target.file).slice(0, 16);
    const targetCiphertext = encryptData(targetKey, target.file);

    const firstIdentity = onlineServerDictionaryAttack(
      targetCiphertext,
      CANDIDATES,
      server,
      "mallory",
    );
    expect(firstIdentity.outcome).toBe("rate-limited");
    const secondIdentity = onlineServerDictionaryAttack(
      targetCiphertext,
      CANDIDATES.slice(1),
      server,
      "sybil-2",
    );
    expect(secondIdentity.outcome).toBe("recovered");

    const compromised = compromisedServerDictionaryAttack(
      targetCiphertext,
      CANDIDATES,
      server,
    );
    expect(compromised.outcome).toBe("recovered");
    expect(compromised.match?.label).toBe("negative result");
    expect(compromised.note).toMatch(/offline/);
  });

  it("returns no-match for a completed compromised-server dictionary", () => {
    const server = new VoprfKeyServer({ seed: new Uint8Array(32).fill(0x88) });
    const targetFile = utf8("absent target");
    const target = encryptData(
      server.compromisedEvaluate(targetFile).slice(0, 16),
      targetFile,
    );
    const result = compromisedServerDictionaryAttack(
      target,
      CANDIDATES,
      server,
    );
    expect(result.outcome).toBe("no-match");
    expect(result.attempted).toBe(CANDIDATES.length);
  });
});
