import {
  decryptData,
  encryptData,
  openDataKeyCapsule,
  wrapDataKey,
} from "../crypto/aes";
import {
  copyBytes,
  equalBytes,
  flipByte,
  randomBytes,
  type ByteRng,
} from "../crypto/bytes";
import {
  deriveServerDataKey,
  finalizeVoprfTranscript,
  VoprfKeyServer,
} from "../crypto/voprf";
import { blobIdOnlyResponse, DedupStore, possessionResponse } from "./storage";

export type BoundaryEvidence = {
  possession: {
    blobIdOnlyRejected: boolean;
    completeCiphertextAccepted: boolean;
    replayRejected: boolean;
    referenceGranted: boolean;
  };
  authorization: {
    crossOwnerReadRejected: boolean;
    ownerReadAccepted: boolean;
  };
  deletion: {
    firstReferenceDeletedBlob: boolean;
    afterFirstReferences: number;
    lastReferenceDeletedBlob: boolean;
    afterLastBlobs: number;
  };
  revocation: {
    futureStorageReadRejected: boolean;
    futureVoprfRejected: boolean;
    cachedCopyStillOpened: boolean;
  };
  rotation: {
    publicKeyChanged: boolean;
    dataKeyChanged: boolean;
    ciphertextChanged: boolean;
    oldCapsuleStillOpened: boolean;
  };
  proofTamperRejected: boolean;
};

type SeededUpload = {
  store: DedupStore;
  server: VoprfKeyServer;
  trustedPublicKey: Uint8Array;
  file: Uint8Array;
  alice: {
    owner: string;
    referenceId: string;
    wrapKey: Uint8Array;
    key: Uint8Array;
    ciphertext: Uint8Array;
    capsule: Uint8Array;
    blobId: string;
  };
  bob: {
    owner: string;
    referenceId: string;
    wrapKey: Uint8Array;
    key: Uint8Array;
    ciphertext: Uint8Array;
    capsule: Uint8Array;
    blobId: string;
  };
};

function seedSharedUpload(file: Uint8Array, rng: ByteRng): SeededUpload {
  const server = new VoprfKeyServer({
    limit: 8,
    authorized: ["alice", "bob", "mallory"],
    seed: rng(32),
  });
  const store = new DedupStore();
  const trustedPublicKey = server.publicKey();
  const records = [];
  for (const owner of ["alice", "bob"] as const) {
    const referenceId = `${owner}-report`;
    const derivation = deriveServerDataKey(
      file,
      server,
      owner,
      trustedPublicKey,
    );
    if (derivation.status !== "ok")
      throw new Error("seed upload unexpectedly refused");
    const wrapKey = rng(32);
    const key = derivation.transcript.dataKey;
    const ciphertext = encryptData(key, file);
    const capsule = wrapDataKey(wrapKey, key, owner, referenceId, ciphertext);
    const stored = store.put({ owner, referenceId, ciphertext, capsule });
    records.push({
      owner,
      referenceId,
      wrapKey: copyBytes(wrapKey),
      key: copyBytes(key),
      ciphertext: copyBytes(ciphertext),
      capsule: copyBytes(capsule),
      blobId: stored.blobId,
    });
  }
  return {
    store,
    server,
    trustedPublicKey,
    file: copyBytes(file),
    alice: records[0],
    bob: records[1],
  };
}

function didThrow(action: () => unknown): boolean {
  try {
    action();
    return false;
  } catch {
    return true;
  }
}

export function runBoundaryDemonstration(
  file: Uint8Array,
  rng: ByteRng = randomBytes,
): BoundaryEvidence {
  const possessionFixture = seedSharedUpload(file, rng);
  const firstChallenge = possessionFixture.store.issuePossessionChallenge(
    possessionFixture.alice.blobId,
    rng,
  );
  const idOnly = blobIdOnlyResponse(
    firstChallenge.nonce,
    firstChallenge.blobId,
  );
  const blobIdOnlyRejected = !possessionFixture.store.verifyPossession(
    firstChallenge.challengeId,
    idOnly,
  );
  const secondChallenge = possessionFixture.store.issuePossessionChallenge(
    possessionFixture.alice.blobId,
    rng,
  );
  const complete = possessionResponse(
    secondChallenge.nonce,
    possessionFixture.alice.ciphertext,
  );
  const completeCiphertextAccepted = possessionFixture.store.verifyPossession(
    secondChallenge.challengeId,
    complete,
  );
  const replayRejected = !possessionFixture.store.verifyPossession(
    secondChallenge.challengeId,
    complete,
  );
  const referenceGranted = !didThrow(() =>
    possessionFixture.store.read("mallory", "alice", "alice-report"),
  );

  const ownerReadAccepted = !didThrow(() =>
    possessionFixture.store.read("alice", "alice", "alice-report"),
  );
  const crossOwnerReadRejected = didThrow(() =>
    possessionFixture.store.read("mallory", "alice", "alice-report"),
  );

  const deletionFixture = seedSharedUpload(file, rng);
  const firstDeletion = deletionFixture.store.deleteReference(
    "alice",
    "alice-report",
  );
  const afterFirstReferences = deletionFixture.store.stats().references;
  const lastDeletion = deletionFixture.store.deleteReference(
    "bob",
    "bob-report",
  );
  const afterLastBlobs = deletionFixture.store.stats().uniqueBlobs;

  const revocationFixture = seedSharedUpload(file, rng);
  const cached = revocationFixture.store.read("alice", "alice", "alice-report");
  revocationFixture.store.revoke("alice");
  revocationFixture.server.revoke("alice");
  const futureStorageReadRejected = didThrow(() =>
    revocationFixture.store.read("alice", "alice", "alice-report"),
  );
  const futureVoprf = deriveServerDataKey(
    file,
    revocationFixture.server,
    "alice",
    revocationFixture.trustedPublicKey,
  );
  const cachedKey = openDataKeyCapsule(
    revocationFixture.alice.wrapKey,
    cached.capsule,
    "alice",
    "alice-report",
    cached.ciphertext,
  );
  const cachedPlaintext = decryptData(cachedKey, cached.ciphertext);

  const rotationFixture = seedSharedUpload(file, rng);
  const oldPublicKey = rotationFixture.server.publicKey();
  const oldKey = copyBytes(rotationFixture.alice.key);
  const oldCiphertext = copyBytes(rotationFixture.alice.ciphertext);
  rotationFixture.server.rotate(rng(32));
  const rotatedPublicKey = rotationFixture.server.publicKey();
  const rotated = deriveServerDataKey(
    file,
    rotationFixture.server,
    "alice",
    rotatedPublicKey,
  );
  if (rotated.status !== "ok")
    throw new Error("rotated key server unexpectedly refused");
  const rotatedCiphertext = encryptData(rotated.transcript.dataKey, file);
  const oldOpenedKey = openDataKeyCapsule(
    rotationFixture.alice.wrapKey,
    rotationFixture.alice.capsule,
    "alice",
    "alice-report",
    oldCiphertext,
  );

  const proofFixture = seedSharedUpload(file, rng);
  const proofTranscript = deriveServerDataKey(
    file,
    proofFixture.server,
    "mallory",
    proofFixture.trustedPublicKey,
  );
  if (proofTranscript.status !== "ok")
    throw new Error("proof fixture unexpectedly refused");
  const proofTamperRejected = didThrow(() =>
    finalizeVoprfTranscript(
      proofTranscript.transcript,
      flipByte(proofTranscript.transcript.proof),
    ),
  );

  return {
    possession: {
      blobIdOnlyRejected,
      completeCiphertextAccepted,
      replayRejected,
      referenceGranted,
    },
    authorization: { crossOwnerReadRejected, ownerReadAccepted },
    deletion: {
      firstReferenceDeletedBlob: firstDeletion.blobDeleted,
      afterFirstReferences,
      lastReferenceDeletedBlob: lastDeletion.blobDeleted,
      afterLastBlobs,
    },
    revocation: {
      futureStorageReadRejected,
      futureVoprfRejected: futureVoprf.status === "principal-rejected",
      cachedCopyStillOpened: equalBytes(cachedPlaintext, file),
    },
    rotation: {
      publicKeyChanged: !equalBytes(
        oldPublicKey,
        rotationFixture.server.publicKey(),
      ),
      dataKeyChanged: !equalBytes(oldKey, rotated.transcript.dataKey),
      ciphertextChanged: !equalBytes(oldCiphertext, rotatedCiphertext),
      oldCapsuleStillOpened: equalBytes(oldOpenedKey, oldKey),
    },
    proofTamperRejected,
  };
}
