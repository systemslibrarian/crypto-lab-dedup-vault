import { p256_oprf } from "@noble/curves/nist.js";
import type { RNG } from "@noble/curves/abstract/oprf.js";

import { copyBytes, randomBytes, type ByteRng, utf8 } from "./bytes";
import { DATA_KEY_BYTES, deriveVoprfInput } from "./aes";

const VOPRF_KEY_INFO = utf8("dedup-vault/v1/key-server");

export function voprfKeyInfo(): Uint8Array {
  return copyBytes(VOPRF_KEY_INFO);
}

function adaptRng(rng?: ByteRng): RNG | undefined {
  if (!rng) return undefined;
  const adapted = (length = 32): Uint8Array<ArrayBuffer> => {
    const source = rng(length);
    const result = new Uint8Array(new ArrayBuffer(source.byteLength));
    result.set(source);
    return result;
  };
  return adapted as RNG;
}

export type VoprfTranscript = {
  input: Uint8Array;
  blind: Uint8Array;
  blinded: Uint8Array;
  evaluated: Uint8Array;
  proof: Uint8Array;
  output: Uint8Array;
  dataKey: Uint8Array;
  publicKey: Uint8Array;
  identity: string;
  epoch: number;
  used: number;
  remaining: number;
};

export type KeyServerRejection = {
  status: "principal-rejected" | "rate-limited";
  identity: string;
  epoch: number;
  used: number;
  remaining: number;
  blinded: Uint8Array;
};

type KeyServerSuccess = {
  status: "ok";
  identity: string;
  epoch: number;
  used: number;
  remaining: number;
  evaluated: Uint8Array;
  proof: Uint8Array;
};

export type ServerDerivation =
  { status: "ok"; transcript: VoprfTranscript } | KeyServerRejection;

export class VoprfKeyServer {
  readonly limit: number;
  #secretKey: Uint8Array;
  #publicKey: Uint8Array;
  #authorized: Set<string>;
  #revoked = new Set<string>();
  #counts = new Map<string, number>();
  #epoch = 1;

  constructor(options?: {
    limit?: number;
    authorized?: string[];
    seed?: Uint8Array;
  }) {
    this.limit = options?.limit ?? 3;
    if (!Number.isInteger(this.limit) || this.limit <= 0) {
      throw new Error(
        "the per-identity epoch limit must be a positive integer",
      );
    }
    this.#authorized = new Set(
      options?.authorized ?? ["alice", "bob", "mallory"],
    );
    const seed = options?.seed ?? randomBytes(32);
    const keys = p256_oprf.voprf.deriveKeyPair(seed, VOPRF_KEY_INFO);
    this.#secretKey = copyBytes(keys.secretKey);
    this.#publicKey = copyBytes(keys.publicKey);
  }

  get epoch(): number {
    return this.#epoch;
  }

  publicKey(): Uint8Array {
    return copyBytes(this.#publicKey);
  }

  count(identity: string): number {
    return this.#counts.get(identity) ?? 0;
  }

  authorize(identity: string): void {
    this.#authorized.add(identity);
    this.#revoked.delete(identity);
  }

  revoke(identity: string): void {
    this.#revoked.add(identity);
  }

  advanceEpoch(): void {
    this.#counts.clear();
    this.#epoch += 1;
  }

  request(
    identity: string,
    blinded: Uint8Array,
    proofRng?: ByteRng,
  ): KeyServerSuccess | Omit<KeyServerRejection, "blinded"> {
    const used = this.count(identity);
    // The modeled external-authentication decision and revocation check happen
    // before either counting or evaluation.
    if (!this.#authorized.has(identity) || this.#revoked.has(identity)) {
      return {
        status: "principal-rejected",
        identity,
        epoch: this.#epoch,
        used,
        remaining: Math.max(0, this.limit - used),
      };
    }
    // The q-th request is allowed; request q + 1 is refused.
    if (used >= this.limit) {
      return {
        status: "rate-limited",
        identity,
        epoch: this.#epoch,
        used,
        remaining: 0,
      };
    }

    const response = p256_oprf.voprf.blindEvaluate(
      this.#secretKey,
      this.#publicKey,
      blinded,
      adaptRng(proofRng),
    );
    const nextUsed = used + 1;
    this.#counts.set(identity, nextUsed);
    return {
      status: "ok",
      identity,
      epoch: this.#epoch,
      used: nextUsed,
      remaining: this.limit - nextUsed,
      evaluated: copyBytes(response.evaluated),
      proof: copyBytes(response.proof),
    };
  }

  compromisedEvaluate(file: Uint8Array): Uint8Array {
    const input = deriveVoprfInput(file);
    const blind = p256_oprf.voprf.blind(input);
    const response = p256_oprf.voprf.blindEvaluate(
      this.#secretKey,
      this.#publicKey,
      blind.blinded,
    );
    return p256_oprf.voprf.finalize(
      input,
      blind.blind,
      response.evaluated,
      blind.blinded,
      this.#publicKey,
      response.proof,
    );
  }

  rotate(seed: Uint8Array = randomBytes(32)): void {
    const keys = p256_oprf.voprf.deriveKeyPair(seed, VOPRF_KEY_INFO);
    this.#secretKey = copyBytes(keys.secretKey);
    this.#publicKey = copyBytes(keys.publicKey);
    this.advanceEpoch();
  }
}

export function deriveServerDataKey(
  file: Uint8Array,
  server: VoprfKeyServer,
  identity: string,
  trustedPublicKey: Uint8Array,
  blindRng?: ByteRng,
  proofRng?: ByteRng,
): ServerDerivation {
  // RFC 9497 proof verification establishes consistency with this client-pinned
  // key. Provisioning an authentic key is deliberately outside this model.
  const pinnedPublicKey = copyBytes(trustedPublicKey);
  const input = deriveVoprfInput(file);
  const blinded = p256_oprf.voprf.blind(input, adaptRng(blindRng));
  const response = server.request(identity, blinded.blinded, proofRng);
  if (response.status !== "ok") {
    return { ...response, blinded: copyBytes(blinded.blinded) };
  }

  // The RFC 9497 finalize call verifies the DLEQ proof before returning output.
  const output = p256_oprf.voprf.finalize(
    input,
    blinded.blind,
    response.evaluated,
    blinded.blinded,
    pinnedPublicKey,
    response.proof,
  );
  return {
    status: "ok",
    transcript: {
      input: copyBytes(input),
      blind: copyBytes(blinded.blind),
      blinded: copyBytes(blinded.blinded),
      evaluated: copyBytes(response.evaluated),
      proof: copyBytes(response.proof),
      output: copyBytes(output),
      dataKey: output.slice(0, DATA_KEY_BYTES),
      publicKey: pinnedPublicKey,
      identity,
      epoch: response.epoch,
      used: response.used,
      remaining: response.remaining,
    },
  };
}

export function finalizeVoprfTranscript(
  transcript: VoprfTranscript,
  proof = transcript.proof,
): Uint8Array {
  return p256_oprf.voprf.finalize(
    transcript.input,
    transcript.blind,
    transcript.evaluated,
    transcript.blinded,
    transcript.publicKey,
    proof,
  );
}
