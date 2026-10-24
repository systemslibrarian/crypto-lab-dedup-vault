import { aessiv, ctr } from "@noble/ciphers/aes.js";

import {
  concatBytes,
  copyBytes,
  domainHash,
  randomBytes,
  sha256Bytes,
  type ByteRng,
  utf8,
} from "./bytes";

export const DATA_KEY_BYTES = 16;
export const USER_WRAP_KEY_BYTES = 32;
const DATA_COUNTER = new Uint8Array(16);
const PUBLIC_PARAMETER = Uint8Array.from([
  0x44, 0x65, 0x64, 0x75, 0x70, 0x20, 0x56, 0x61, 0x75, 0x6c, 0x74, 0x20, 0x76,
  0x31, 0x00, 0x01,
]);

export function publicParameter(): Uint8Array {
  return copyBytes(PUBLIC_PARAMETER);
}

function requireLength(value: Uint8Array, length: number, name: string): void {
  if (value.length !== length)
    throw new Error(`${name} must be ${length} bytes`);
}

function requireWellFormedUnicode(value: string, name: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff) {
        throw new Error(`${name} must be well-formed Unicode`);
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new Error(`${name} must be well-formed Unicode`);
    }
  }
}

export function freshDataKey(rng: ByteRng = randomBytes): Uint8Array {
  const key = rng(DATA_KEY_BYTES);
  requireLength(key, DATA_KEY_BYTES, "data key");
  return copyBytes(key);
}

export function freshUserWrapKey(rng: ByteRng = randomBytes): Uint8Array {
  const key = rng(USER_WRAP_KEY_BYTES);
  requireLength(key, USER_WRAP_KEY_BYTES, "user wrapping key");
  return copyBytes(key);
}

export function deriveLocalDataKey(file: Uint8Array): Uint8Array {
  if (file.length === 0)
    throw new Error("the teaching model requires a non-empty file");
  // DupLESS §4 instantiates convergent encryption as first128(SHA-256(P || M)).
  return sha256Bytes(concatBytes(PUBLIC_PARAMETER, file)).slice(
    0,
    DATA_KEY_BYTES,
  );
}

export function encryptData(
  key: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  requireLength(key, DATA_KEY_BYTES, "data key");
  if (plaintext.length === 0)
    throw new Error("the teaching model requires a non-empty file");
  return ctr(key, DATA_COUNTER).encrypt(plaintext);
}

export function decryptData(
  key: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  requireLength(key, DATA_KEY_BYTES, "data key");
  if (ciphertext.length === 0) throw new Error("ciphertext must not be empty");
  return ctr(key, DATA_COUNTER).decrypt(ciphertext);
}

export function capsuleAssociatedData(
  owner: string,
  referenceId: string,
  dataCiphertext: Uint8Array,
): Uint8Array[] {
  if (owner.length === 0 || referenceId.length === 0) {
    throw new Error("capsules require a non-empty owner and reference");
  }
  requireWellFormedUnicode(owner, "capsule owner");
  requireWellFormedUnicode(referenceId, "capsule reference");
  if (dataCiphertext.length === 0)
    throw new Error("capsules require data ciphertext");
  return [
    utf8("dedup-vault/capsule/v1"),
    utf8(owner),
    utf8(referenceId),
    copyBytes(dataCiphertext),
  ];
}

export function wrapDataKey(
  userWrapKey: Uint8Array,
  dataKey: Uint8Array,
  owner: string,
  referenceId: string,
  dataCiphertext: Uint8Array,
): Uint8Array {
  requireLength(userWrapKey, USER_WRAP_KEY_BYTES, "user wrapping key");
  requireLength(dataKey, DATA_KEY_BYTES, "data key");
  return aessiv(
    userWrapKey,
    ...capsuleAssociatedData(owner, referenceId, dataCiphertext),
  ).encrypt(dataKey);
}

export function openDataKeyCapsule(
  userWrapKey: Uint8Array,
  capsule: Uint8Array,
  owner: string,
  referenceId: string,
  dataCiphertext: Uint8Array,
): Uint8Array {
  requireLength(userWrapKey, USER_WRAP_KEY_BYTES, "user wrapping key");
  const key = aessiv(
    userWrapKey,
    ...capsuleAssociatedData(owner, referenceId, dataCiphertext),
  ).decrypt(capsule);
  requireLength(key, DATA_KEY_BYTES, "opened data key");
  return key;
}

export function deriveVoprfInput(file: Uint8Array): Uint8Array {
  if (file.length === 0)
    throw new Error("the teaching model requires a non-empty file");
  return domainHash("dedup-vault/v1/voprf-input", PUBLIC_PARAMETER, file);
}

export function capsuleStorageBytes(capsules: Uint8Array[]): number {
  return capsules.reduce((total, capsule) => total + capsule.length, 0);
}

export function localDerivationTranscript(file: Uint8Array): Uint8Array {
  return concatBytes(PUBLIC_PARAMETER, file);
}
