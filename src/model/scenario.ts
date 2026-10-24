import {
  decryptData,
  deriveLocalDataKey,
  encryptData,
  freshDataKey,
  freshUserWrapKey,
  openDataKeyCapsule,
  wrapDataKey,
} from "../crypto/aes";
import {
  copyBytes,
  equalBytes,
  randomBytes,
  type ByteRng,
} from "../crypto/bytes";
import {
  deriveServerDataKey,
  VoprfKeyServer,
  type VoprfTranscript,
} from "../crypto/voprf";
import { DedupStore } from "./storage";

export type DedupMode = "fresh" | "local-mle" | "server-aided";

export type UploadEvidence = {
  owner: string;
  referenceId: string;
  dataKey: Uint8Array;
  dataCiphertext: Uint8Array;
  capsule: Uint8Array;
  blobId: string;
  deduplicated: boolean;
  userWrapKey: Uint8Array;
  voprf?: VoprfTranscript;
};

export type ModeEvidence = {
  mode: DedupMode;
  uploads: UploadEvidence[];
  equalDataCiphertexts: boolean;
  distinctCapsules: boolean;
  logicalDataBytes: number;
  uniqueDataBytes: number;
  capsuleBytes: number;
  totalStoredBytes: number;
  uniqueBlobs: number;
  references: number;
  dataDedupRatio: number;
  store: DedupStore;
};

export type ComparisonEvidence = {
  file: Uint8Array;
  modes: Record<DedupMode, ModeEvidence>;
  server: VoprfKeyServer;
};

const OWNERS = ["alice", "bob"] as const;

function runMode(
  mode: DedupMode,
  file: Uint8Array,
  rng: ByteRng,
  server: VoprfKeyServer,
  trustedPublicKey: Uint8Array,
  userWrapKeys: Map<string, Uint8Array>,
): ModeEvidence {
  const store = new DedupStore();
  const uploads: UploadEvidence[] = [];

  for (const owner of OWNERS) {
    const referenceId = `${owner}-report`;
    let dataKey: Uint8Array;
    let voprf: VoprfTranscript | undefined;
    if (mode === "fresh") {
      // Each upload draws a new key, so equal files intentionally do not deduplicate.
      dataKey = freshDataKey(rng);
    } else if (mode === "local-mle") {
      dataKey = deriveLocalDataKey(file);
    } else {
      const derivation = deriveServerDataKey(
        file,
        server,
        owner,
        trustedPublicKey,
      );
      if (derivation.status !== "ok") {
        throw new Error(
          `unexpected key-server refusal for ${owner}: ${derivation.status}`,
        );
      }
      dataKey = copyBytes(derivation.transcript.dataKey);
      voprf = derivation.transcript;
    }

    const dataCiphertext = encryptData(dataKey, file);
    const userWrapKey = userWrapKeys.get(owner);
    if (!userWrapKey) throw new Error(`missing user wrapping key for ${owner}`);
    const capsule = wrapDataKey(
      userWrapKey,
      dataKey,
      owner,
      referenceId,
      dataCiphertext,
    );
    const stored = store.put({
      owner,
      referenceId,
      ciphertext: dataCiphertext,
      capsule,
    });
    uploads.push({
      owner,
      referenceId,
      dataKey: copyBytes(dataKey),
      dataCiphertext: copyBytes(dataCiphertext),
      capsule: copyBytes(capsule),
      blobId: stored.blobId,
      deduplicated: stored.deduplicated,
      userWrapKey: copyBytes(userWrapKey),
      voprf,
    });
  }

  const stats = store.stats();
  const logicalDataBytes = file.length * OWNERS.length;
  return {
    mode,
    uploads,
    equalDataCiphertexts: equalBytes(
      uploads[0].dataCiphertext,
      uploads[1].dataCiphertext,
    ),
    distinctCapsules: !equalBytes(uploads[0].capsule, uploads[1].capsule),
    logicalDataBytes,
    ...stats,
    dataDedupRatio: logicalDataBytes / stats.uniqueDataBytes,
    store,
  };
}

export function runComparison(
  file: Uint8Array,
  options?: { rng?: ByteRng; server?: VoprfKeyServer },
): ComparisonEvidence {
  if (file.length === 0) throw new Error("comparison file must not be empty");
  const rng = options?.rng ?? randomBytes;
  const server =
    options?.server ??
    new VoprfKeyServer({ limit: 8, authorized: [...OWNERS, "mallory"] });
  const trustedPublicKey = server.publicKey();
  const userWrapKeys = new Map<string, Uint8Array>(
    OWNERS.map((owner) => [owner, freshUserWrapKey(rng)]),
  );

  return {
    file: copyBytes(file),
    modes: {
      fresh: runMode(
        "fresh",
        file,
        rng,
        server,
        trustedPublicKey,
        userWrapKeys,
      ),
      "local-mle": runMode(
        "local-mle",
        file,
        rng,
        server,
        trustedPublicKey,
        userWrapKeys,
      ),
      "server-aided": runMode(
        "server-aided",
        file,
        rng,
        server,
        trustedPublicKey,
        userWrapKeys,
      ),
    },
    server,
  };
}

export function retrieveUpload(upload: UploadEvidence): Uint8Array {
  const key = openDataKeyCapsule(
    upload.userWrapKey,
    upload.capsule,
    upload.owner,
    upload.referenceId,
    upload.dataCiphertext,
  );
  return decryptData(key, upload.dataCiphertext);
}
