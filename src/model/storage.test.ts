import { describe, expect, it } from "vitest";

import { flipByte, utf8 } from "../crypto/bytes";
import { blobIdOnlyResponse, DedupStore, possessionResponse } from "./storage";

function put(
  store: DedupStore,
  owner: string,
  referenceId: string,
  ciphertext: Uint8Array,
  indexOverride?: string,
) {
  return store.put({
    owner,
    referenceId,
    ciphertext,
    capsule: utf8(`capsule:${owner}:${referenceId}`),
    indexOverride,
  });
}

describe("exact-byte deduplicating storage", () => {
  it("deduplicates equal ciphertext and accounts for data, capsules, and references", () => {
    const store = new DedupStore();
    const ciphertext = utf8("same ciphertext");
    expect(put(store, "alice", "a", ciphertext).deduplicated).toBe(false);
    expect(put(store, "bob", "b", ciphertext).deduplicated).toBe(true);
    expect(store.stats()).toEqual({
      uniqueBlobs: 1,
      references: 2,
      uniqueDataBytes: ciphertext.length,
      capsuleBytes:
        utf8("capsule:alice:a").length + utf8("capsule:bob:b").length,
      totalStoredBytes:
        ciphertext.length +
        utf8("capsule:alice:a").length +
        utf8("capsule:bob:b").length,
    });
  });

  it("(DV-06) does not merge unequal ciphertext even under a forced digest collision", () => {
    const store = new DedupStore();
    put(store, "alice", "a", utf8("first"), "forced-collision");
    const second = put(store, "bob", "b", utf8("second"), "forced-collision");
    expect(second.deduplicated).toBe(false);
    expect(store.stats().uniqueBlobs).toBe(2);
    expect(store.snapshot().map((blob) => blob.index)).toEqual([
      "forced-collision",
      "forced-collision",
    ]);
  });

  it("(DV-14) never reuses a blob identifier after deletion inside a collision bucket", () => {
    const store = new DedupStore();
    const first = put(store, "alice", "a", utf8("first"), "forced-collision");
    const survivor = put(store, "bob", "b", utf8("second"), "forced-collision");
    expect(store.deleteReference("alice", "a").blobDeleted).toBe(true);
    const replacement = put(
      store,
      "carol",
      "c",
      utf8("third"),
      "forced-collision",
    );

    expect(
      new Set([first.blobId, survivor.blobId, replacement.blobId]).size,
    ).toBe(3);
    expect(store.snapshot().map((blob) => blob.blobId)).toEqual([
      survivor.blobId,
      replacement.blobId,
    ]);
  });

  it("keeps authorization separate from references and revocation", () => {
    const store = new DedupStore();
    put(store, "alice", "report", utf8("ciphertext"));
    expect(store.read("alice", "alice", "report").ciphertext).toEqual(
      utf8("ciphertext"),
    );
    expect(() => store.read("mallory", "alice", "report")).toThrow(
      /not authorized/,
    );
    store.revoke("alice");
    expect(() => store.read("alice", "alice", "report")).toThrow(/revoked/);
    expect(() => store.read("alice", "alice", "missing")).toThrow(/revoked/);
  });

  it("(DV-17) keeps formerly ambiguous owner/reference tuples distinct", () => {
    const store = new DedupStore();
    expect(() => {
      put(store, "a\u0000b", "c", utf8("first"));
      put(store, "a", "b\u0000c", utf8("second"));
    }).not.toThrow();

    expect(store.stats().references).toBe(2);
    expect(store.read("a\u0000b", "a\u0000b", "c").ciphertext).toEqual(
      utf8("first"),
    );
    expect(store.read("a", "a", "b\u0000c").ciphertext).toEqual(utf8("second"));
  });

  it("(DV-08) removes a shared blob only after the last reference", () => {
    const store = new DedupStore();
    put(store, "alice", "a", utf8("same"));
    put(store, "bob", "b", utf8("same"));
    expect(store.deleteReference("alice", "a")).toEqual({
      blobDeleted: false,
      remainingReferences: 1,
    });
    expect(store.stats().uniqueBlobs).toBe(1);
    expect(store.deleteReference("bob", "b")).toEqual({
      blobDeleted: true,
      remainingReferences: 0,
    });
    expect(store.stats().uniqueBlobs).toBe(0);
    expect(() => store.deleteReference("bob", "b")).toThrow(/not found/);
  });

  it("(DV-07 DV-20) requires a fresh nonce and the complete ciphertext for bounded possession", () => {
    const store = new DedupStore();
    const ciphertext = utf8("complete stored ciphertext");
    const stored = put(store, "alice", "a", ciphertext);
    let nonceValue = 0x40;
    const freshNonceRng = () => new Uint8Array(16).fill(nonceValue++);

    const idChallenge = store.issuePossessionChallenge(
      stored.blobId,
      freshNonceRng,
    );
    expect(
      store.verifyPossession(
        idChallenge.challengeId,
        blobIdOnlyResponse(idChallenge.nonce, stored.blobId),
      ),
    ).toBe(false);

    const challenge = store.issuePossessionChallenge(
      stored.blobId,
      freshNonceRng,
    );
    const correct = possessionResponse(challenge.nonce, ciphertext);
    expect(
      store.verifyPossession(challenge.challengeId, flipByte(correct)),
    ).toBe(false);
    const accepted = store.issuePossessionChallenge(
      stored.blobId,
      freshNonceRng,
    );
    const acceptedResponse = possessionResponse(accepted.nonce, ciphertext);
    expect(store.verifyPossession(accepted.challengeId, acceptedResponse)).toBe(
      true,
    );
    expect(store.verifyPossession(accepted.challengeId, acceptedResponse)).toBe(
      false,
    );
    const freshChallenge = store.issuePossessionChallenge(
      stored.blobId,
      freshNonceRng,
    );
    expect(freshChallenge.nonce).not.toEqual(accepted.nonce);
    expect(
      store.verifyPossession(freshChallenge.challengeId, acceptedResponse),
    ).toBe(false);
    expect(() =>
      store.issuePossessionChallenge("missing", freshNonceRng),
    ).toThrow(/not found/);
    expect(() =>
      store.issuePossessionChallenge(stored.blobId, () => new Uint8Array(15)),
    ).toThrow(/16 bytes/);
  });

  it("rejects missing fields and duplicate references", () => {
    const store = new DedupStore();
    expect(() =>
      store.put({
        owner: "",
        referenceId: "r",
        ciphertext: utf8("c"),
        capsule: utf8("x"),
      }),
    ).toThrow(/required/);
    expect(() =>
      store.put({
        owner: "a",
        referenceId: "r",
        ciphertext: new Uint8Array(),
        capsule: utf8("x"),
      }),
    ).toThrow(/required/);
    put(store, "alice", "a", utf8("same"));
    expect(() => put(store, "alice", "a", utf8("same"))).toThrow(
      /already exists/,
    );
    expect(() => store.read("alice", "alice", "missing")).toThrow(/not found/);
  });
});
