import { deriveLocalDataKey, encryptData } from "../crypto/aes";
import { copyBytes, equalBytes } from "../crypto/bytes";
import { deriveServerDataKey, type VoprfKeyServer } from "../crypto/voprf";

export type DictionaryCandidate = {
  label: string;
  file: Uint8Array;
};

export type DictionaryResult = {
  outcome: "recovered" | "no-match" | "rate-limited" | "principal-rejected";
  match?: DictionaryCandidate;
  attempted: number;
  comparedCiphertexts: Uint8Array[];
  note: string;
};

export function offlineDictionaryAttack(
  targetCiphertext: Uint8Array,
  candidates: DictionaryCandidate[],
): DictionaryResult {
  const comparedCiphertexts: Uint8Array[] = [];
  for (const candidate of candidates) {
    const guess = encryptData(
      deriveLocalDataKey(candidate.file),
      candidate.file,
    );
    comparedCiphertexts.push(copyBytes(guess));
    if (equalBytes(guess, targetCiphertext)) {
      return {
        outcome: "recovered",
        match: candidate,
        attempted: comparedCiphertexts.length,
        comparedCiphertexts,
        note: "Exact ciphertext equality identified the candidate.",
      };
    }
  }
  return {
    outcome: "no-match",
    attempted: comparedCiphertexts.length,
    comparedCiphertexts,
    note: "No listed candidate produced the target ciphertext; this does not prove high entropy.",
  };
}

export function onlineServerDictionaryAttack(
  targetCiphertext: Uint8Array,
  candidates: DictionaryCandidate[],
  server: VoprfKeyServer,
  identity: string,
): DictionaryResult {
  const comparedCiphertexts: Uint8Array[] = [];
  // Pin before the sequence of requests. Authentic provisioning of this key is
  // an external assumption, distinct from the VOPRF proof itself.
  const trustedPublicKey = server.publicKey();
  for (const candidate of candidates) {
    const derivation = deriveServerDataKey(
      candidate.file,
      server,
      identity,
      trustedPublicKey,
    );
    if (derivation.status !== "ok") {
      return {
        outcome: derivation.status,
        attempted: comparedCiphertexts.length,
        comparedCiphertexts,
        note:
          derivation.status === "rate-limited"
            ? "The next guess was delayed by the modeled epoch budget, not proved impossible."
            : "The key server rejected a principal outside the modeled allowlist, or a revoked principal, before evaluation.",
      };
    }
    const guess = encryptData(derivation.transcript.dataKey, candidate.file);
    comparedCiphertexts.push(copyBytes(guess));
    if (equalBytes(guess, targetCiphertext)) {
      return {
        outcome: "recovered",
        match: candidate,
        attempted: comparedCiphertexts.length,
        comparedCiphertexts,
        note: "The target fell inside this identity’s online request budget.",
      };
    }
  }
  return {
    outcome: "no-match",
    attempted: comparedCiphertexts.length,
    comparedCiphertexts,
    note: "No listed candidate matched within the completed online search.",
  };
}

export function compromisedServerDictionaryAttack(
  targetCiphertext: Uint8Array,
  candidates: DictionaryCandidate[],
  server: VoprfKeyServer,
): DictionaryResult {
  const comparedCiphertexts: Uint8Array[] = [];
  for (const candidate of candidates) {
    const dataKey = server.compromisedEvaluate(candidate.file).slice(0, 16);
    const guess = encryptData(dataKey, candidate.file);
    comparedCiphertexts.push(copyBytes(guess));
    if (equalBytes(guess, targetCiphertext)) {
      return {
        outcome: "recovered",
        match: candidate,
        attempted: comparedCiphertexts.length,
        comparedCiphertexts,
        note: "The compromised key server evaluated candidates offline against stored ciphertext.",
      };
    }
  }
  return {
    outcome: "no-match",
    attempted: comparedCiphertexts.length,
    comparedCiphertexts,
    note: "No listed candidate matched; compromise still removed the online rate boundary.",
  };
}
