import {
  bytesToHex,
  copyBytes,
  domainHash,
  equalBytes,
  randomBytes,
  sha256Bytes,
  type ByteRng,
  utf8,
} from "../crypto/bytes";

export type StoredReference = {
  owner: string;
  referenceId: string;
  capsule: Uint8Array;
};

export type StoredBlob = {
  blobId: string;
  index: string;
  ciphertext: Uint8Array;
  references: StoredReference[];
};

type InternalBlob = {
  blobId: string;
  index: string;
  ciphertext: Uint8Array;
  references: Map<string, StoredReference>;
};

type PossessionChallenge = {
  challengeId: string;
  blobId: string;
  nonce: Uint8Array;
};

function referenceKey(owner: string, referenceId: string): string {
  // JSON's escaped, length-delimited string tuple is injective for JavaScript
  // strings, including embedded NULs; delimiter concatenation is not.
  return JSON.stringify([owner, referenceId]);
}

function cloneReference(reference: StoredReference): StoredReference {
  return { ...reference, capsule: copyBytes(reference.capsule) };
}

export class DedupStore {
  #buckets = new Map<string, InternalBlob[]>();
  #references = new Map<string, InternalBlob>();
  #revoked = new Set<string>();
  #challenges = new Map<string, PossessionChallenge>();
  #challengeSequence = 0;
  #blobSequence = 0;

  put(input: {
    owner: string;
    referenceId: string;
    ciphertext: Uint8Array;
    capsule: Uint8Array;
    indexOverride?: string;
  }): { blobId: string; deduplicated: boolean; index: string } {
    if (!input.owner || !input.referenceId)
      throw new Error("owner and reference are required");
    if (input.ciphertext.length === 0 || input.capsule.length === 0) {
      throw new Error("ciphertext and capsule are required");
    }
    const key = referenceKey(input.owner, input.referenceId);
    if (this.#references.has(key))
      throw new Error("that owner/reference already exists");

    const index =
      input.indexOverride ?? bytesToHex(sha256Bytes(input.ciphertext));
    const bucket = this.#buckets.get(index) ?? [];
    // A digest selects a bucket; only complete ciphertext equality permits deduplication.
    let blob = bucket.find((candidate) =>
      equalBytes(candidate.ciphertext, input.ciphertext),
    );
    const deduplicated = blob !== undefined;
    if (!blob) {
      this.#blobSequence += 1;
      blob = {
        blobId: `blob-${this.#blobSequence}`,
        index,
        ciphertext: copyBytes(input.ciphertext),
        references: new Map(),
      };
      bucket.push(blob);
      this.#buckets.set(index, bucket);
    }

    blob.references.set(key, {
      owner: input.owner,
      referenceId: input.referenceId,
      capsule: copyBytes(input.capsule),
    });
    this.#references.set(key, blob);
    return { blobId: blob.blobId, deduplicated, index };
  }

  read(
    requester: string,
    owner: string,
    referenceId: string,
  ): {
    ciphertext: Uint8Array;
    capsule: Uint8Array;
    blobId: string;
  } {
    if (this.#revoked.has(requester)) throw new Error("requester is revoked");
    if (requester !== owner)
      throw new Error("requester is not authorized for this reference");
    const key = referenceKey(owner, referenceId);
    const blob = this.#references.get(key);
    const reference = blob?.references.get(key);
    if (!blob || !reference) throw new Error("reference not found");
    return {
      ciphertext: copyBytes(blob.ciphertext),
      capsule: copyBytes(reference.capsule),
      blobId: blob.blobId,
    };
  }

  revoke(owner: string): void {
    this.#revoked.add(owner);
  }

  deleteReference(
    owner: string,
    referenceId: string,
  ): {
    blobDeleted: boolean;
    remainingReferences: number;
  } {
    const key = referenceKey(owner, referenceId);
    const blob = this.#references.get(key);
    if (!blob) throw new Error("reference not found");
    blob.references.delete(key);
    this.#references.delete(key);
    if (blob.references.size === 0) {
      const bucket = this.#buckets.get(blob.index) ?? [];
      const remaining = bucket.filter((candidate) => candidate !== blob);
      if (remaining.length === 0) this.#buckets.delete(blob.index);
      else this.#buckets.set(blob.index, remaining);
      return { blobDeleted: true, remainingReferences: 0 };
    }
    return { blobDeleted: false, remainingReferences: blob.references.size };
  }

  issuePossessionChallenge(
    blobId: string,
    rng: ByteRng = randomBytes,
  ): PossessionChallenge {
    const blob = this.#findBlob(blobId);
    if (!blob) throw new Error("blob not found");
    const nonce = rng(16);
    if (nonce.length !== 16)
      throw new Error("possession nonce must be 16 bytes");
    this.#challengeSequence += 1;
    const challenge: PossessionChallenge = {
      challengeId: `challenge-${this.#challengeSequence}`,
      blobId,
      nonce: copyBytes(nonce),
    };
    this.#challenges.set(challenge.challengeId, challenge);
    return { ...challenge, nonce: copyBytes(nonce) };
  }

  verifyPossession(challengeId: string, response: Uint8Array): boolean {
    const challenge = this.#challenges.get(challengeId);
    if (!challenge) return false;
    this.#challenges.delete(challengeId);
    const blob = this.#findBlob(challenge.blobId);
    if (!blob) return false;
    const expected = possessionResponse(challenge.nonce, blob.ciphertext);
    return equalBytes(expected, response);
  }

  stats(): {
    uniqueBlobs: number;
    references: number;
    uniqueDataBytes: number;
    capsuleBytes: number;
    totalStoredBytes: number;
  } {
    const blobs = this.snapshot();
    const uniqueDataBytes = blobs.reduce(
      (total, blob) => total + blob.ciphertext.length,
      0,
    );
    const capsuleBytes = blobs.reduce(
      (total, blob) =>
        total +
        blob.references.reduce(
          (sum, reference) => sum + reference.capsule.length,
          0,
        ),
      0,
    );
    const references = blobs.reduce(
      (total, blob) => total + blob.references.length,
      0,
    );
    return {
      uniqueBlobs: blobs.length,
      references,
      uniqueDataBytes,
      capsuleBytes,
      totalStoredBytes: uniqueDataBytes + capsuleBytes,
    };
  }

  snapshot(): StoredBlob[] {
    return Array.from(this.#buckets.values())
      .flat()
      .map((blob) => ({
        blobId: blob.blobId,
        index: blob.index,
        ciphertext: copyBytes(blob.ciphertext),
        references: Array.from(blob.references.values(), cloneReference),
      }));
  }

  #findBlob(blobId: string): InternalBlob | undefined {
    for (const bucket of this.#buckets.values()) {
      const blob = bucket.find((candidate) => candidate.blobId === blobId);
      if (blob) return blob;
    }
    return undefined;
  }
}

export function possessionResponse(
  nonce: Uint8Array,
  completeCiphertext: Uint8Array,
): Uint8Array {
  return domainHash(
    "dedup-vault/v1/whole-ciphertext-possession",
    nonce,
    completeCiphertext,
  );
}

export function blobIdOnlyResponse(
  nonce: Uint8Array,
  blobId: string,
): Uint8Array {
  return domainHash(
    "dedup-vault/v1/whole-ciphertext-possession",
    nonce,
    utf8(blobId),
  );
}
