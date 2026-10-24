import { describe, expect, it } from "vitest";

import { utf8, type ByteRng } from "../crypto/bytes";
import { runBoundaryDemonstration } from "./boundaries";

function deterministicRng(): ByteRng {
  let call = 0;
  return (length) => {
    call += 1;
    return Uint8Array.from(
      { length },
      (_, index) => (call * 19 + index * 7) & 0xff,
    );
  };
}

describe("possession, authorization, deletion, revocation, and rotation boundaries", () => {
  it("(DV-09 DV-12) executes every boundary and retains the stated negative cases", () => {
    const result = runBoundaryDemonstration(
      utf8("shared synthetic evidence"),
      deterministicRng(),
    );
    expect(result).toEqual({
      possession: {
        blobIdOnlyRejected: true,
        completeCiphertextAccepted: true,
        replayRejected: true,
        referenceGranted: false,
      },
      authorization: {
        crossOwnerReadRejected: true,
        ownerReadAccepted: true,
      },
      deletion: {
        firstReferenceDeletedBlob: false,
        afterFirstReferences: 1,
        lastReferenceDeletedBlob: true,
        afterLastBlobs: 0,
      },
      revocation: {
        futureStorageReadRejected: true,
        futureVoprfRejected: true,
        cachedCopyStillOpened: true,
      },
      rotation: {
        publicKeyChanged: true,
        dataKeyChanged: true,
        ciphertextChanged: true,
        oldCapsuleStillOpened: true,
      },
      proofTamperRejected: true,
    });
  });
});
