import { sha256 } from "@noble/hashes/sha2.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export type ByteRng = (length: number) => Uint8Array;

export function utf8(value: string): Uint8Array {
  return encoder.encode(value);
}

export function decodeUtf8(value: Uint8Array): string {
  return decoder.decode(value);
}

export function concatBytes(...values: Uint8Array[]): Uint8Array {
  const length = values.reduce((total, value) => total + value.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}

export function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

export function hexToBytes(value: string): Uint8Array {
  const normalized = value.replaceAll(/\s+/g, "").toLowerCase();
  if (!/^[0-9a-f]*$/.test(normalized) || normalized.length % 2 !== 0) {
    throw new Error("hex input must contain complete hexadecimal bytes");
  }
  return Uint8Array.from(
    normalized.match(/.{2}/g)?.map((byte) => Number.parseInt(byte, 16)) ?? [],
  );
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length <= 0) {
    throw new Error("random byte length must be a positive integer");
  }
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

function u32(value: number): Uint8Array {
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value, false);
  return output;
}

export function domainHash(label: string, ...parts: Uint8Array[]): Uint8Array {
  const encodedLabel = utf8(label);
  const framed = [u32(encodedLabel.length), encodedLabel];
  for (const part of parts) framed.push(u32(part.length), part);
  return sha256(concatBytes(...framed));
}

export function sha256Bytes(value: Uint8Array): Uint8Array {
  return sha256(value);
}

export function copyBytes(value: Uint8Array): Uint8Array {
  return Uint8Array.from(value);
}

export function flipByte(value: Uint8Array, index = 0): Uint8Array {
  if (index < 0 || index >= value.length)
    throw new Error("byte index is out of range");
  const output = copyBytes(value);
  output[index] ^= 0x01;
  return output;
}
