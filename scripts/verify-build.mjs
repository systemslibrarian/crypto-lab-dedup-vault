#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const noticePath = path.join(root, "dist", "THIRD_PARTY_NOTICES.txt");
const notice = fs.readFileSync(noticePath, "utf8");

for (const required of [
  "@noble/ciphers 2.4.0",
  "@noble/curves 2.4.0",
  "@noble/hashes 2.4.0",
  "Copyright (c) 2016 Thomas Pornin",
  "Permission is hereby granted, free of charge",
  'THE SOFTWARE IS PROVIDED "AS IS"',
]) {
  if (!notice.includes(required)) {
    throw new Error(`deployed third-party notice is missing: ${required}`);
  }
}

console.info("build evidence: deployed runtime license notices present");
