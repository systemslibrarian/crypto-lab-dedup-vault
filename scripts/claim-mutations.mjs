#!/usr/bin/env node
/**
 * Source-mutation gate for Dedup Vault's central learner-visible claims.
 *
 * Run only from a clean commit. The runner proves the unmodified unit/browser
 * baseline first, changes exactly one source file at a time, requires the
 * owning assertion to fail normally, restores the exact saved bytes, and
 * re-proves that assertion. Evidence is written below ignored test-results/.
 */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const RESULT_ROOT = path.join(ROOT, "test-results", "claim-mutations");
const HEAD = git(["rev-parse", "HEAD"]).trim();
const CHILD_ENV = { ...process.env, CI: "1", FORCE_COLOR: "0" };

const unit = (file, id) => ({
  program: "npx",
  args: ["--no-install", "vitest", "run", file, "-t", id, "--reporter=verbose"],
});
const browser = (id) => ({
  program: "npx",
  args: [
    "--no-install",
    "playwright",
    "test",
    "e2e/claims.spec.ts",
    "--grep",
    id,
    "--workers=1",
    "--retries=0",
    "--reporter=line",
  ],
});

const MUTATIONS = [
  {
    id: "DV-01",
    finding:
      "Fresh mode must draw independent keys rather than become deterministic.",
    file: "src/model/scenario.ts",
    anchor: "dataKey = freshDataKey(rng);",
    replacement: "dataKey = deriveLocalDataKey(file);",
    target: unit("src/model/scenario.test.ts", "DV-01"),
  },
  {
    id: "DV-02",
    finding: "Local MLE derivation must commit to the complete file.",
    file: "src/crypto/aes.ts",
    anchor: "sha256Bytes(concatBytes(PUBLIC_PARAMETER, file))",
    replacement: "sha256Bytes(PUBLIC_PARAMETER)",
    target: unit("src/crypto/aes.test.ts", "DV-02"),
  },
  {
    id: "DV-03",
    finding: "A transcript helper must not bypass VOPRF proof verification.",
    file: "src/crypto/voprf.ts",
    anchor: `export function finalizeVoprfTranscript(
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
}`,
    replacement: `export function finalizeVoprfTranscript(
  transcript: VoprfTranscript,
  proof = transcript.proof,
): Uint8Array {
  void proof;
  return copyBytes(transcript.output);
}`,
    target: unit("src/crypto/voprf.test.ts", "DV-03"),
  },
  {
    id: "DV-04",
    finding:
      "The principal allowlist/revocation decision must precede evaluation.",
    file: "src/crypto/voprf.ts",
    anchor:
      "if (!this.#authorized.has(identity) || this.#revoked.has(identity)) {",
    replacement: "if (false) {",
    target: unit("src/crypto/voprf.test.ts", "DV-04"),
  },
  {
    id: "DV-05",
    finding: "Exactly q requests are allowed; q + 1 must be refused.",
    file: "src/crypto/voprf.ts",
    anchor: "if (used >= this.limit) {",
    replacement: "if (used > this.limit) {",
    target: unit("src/crypto/voprf.test.ts", "DV-05"),
  },
  {
    id: "DV-06",
    finding: "A digest bucket must not replace complete ciphertext equality.",
    file: "src/model/storage.ts",
    anchor: `let blob = bucket.find((candidate) =>
      equalBytes(candidate.ciphertext, input.ciphertext),
    );`,
    replacement: "let blob = bucket[0];",
    target: unit("src/model/storage.test.ts", "DV-06"),
  },
  {
    id: "DV-07",
    finding:
      "Possession must commit to complete ciphertext, not only its identifier.",
    file: "src/model/storage.ts",
    anchor:
      "const expected = possessionResponse(challenge.nonce, blob.ciphertext);",
    replacement:
      "const expected = blobIdOnlyResponse(challenge.nonce, challenge.blobId);",
    target: unit("src/model/storage.test.ts", "DV-07"),
  },
  {
    id: "DV-08",
    finding: "Deleting the first reference must retain a shared blob.",
    file: "src/model/storage.ts",
    anchor: "if (blob.references.size === 0) {",
    replacement: "if (blob.references.size <= 1) {",
    target: unit("src/model/storage.test.ts", "DV-08"),
  },
  {
    id: "DV-09",
    finding: "Successful possession must not create authorization.",
    file: "src/model/boundaries.ts",
    anchor: "      referenceGranted,",
    replacement: "      referenceGranted: true,",
    target: unit("src/model/boundaries.test.ts", "DV-09"),
  },
  {
    id: "DV-10",
    finding: "Changing the synthetic file must retire every displayed result.",
    file: "src/main.ts",
    anchor: 'input.addEventListener("input", markStale);',
    replacement: "void markStale;",
    target: browser("DV-10"),
  },
  {
    id: "DV-11",
    finding:
      "The learner UI must retain the exact-construction adaptation warning.",
    file: "src/main.ts",
    anchor:
      "This is not the exact DupLESS construction: it replaces the blind-RSA OPRF with a P-256 VOPRF, replaces DupLESS’s HMAC-SHA256/AES-CTR SIV capsule with RFC 5297 AES-CMAC-SIV, and omits its path/name handling. The original proof does not transfer automatically.",
    replacement: "This construction uses an OPRF and a capsule.",
    target: browser("DV-11"),
  },
  {
    id: "DV-12",
    finding:
      "Revocation must not be presented as erasing an already cached copy.",
    file: "src/model/boundaries.ts",
    anchor: "cachedCopyStillOpened: equalBytes(cachedPlaintext, file),",
    replacement: "cachedCopyStillOpened: false,",
    target: unit("src/model/boundaries.test.ts", "DV-12"),
  },
  {
    id: "DV-13",
    finding:
      "Advancing a rate epoch must actually renew the per-principal budget.",
    file: "src/crypto/voprf.ts",
    anchor: `advanceEpoch(): void {
    this.#counts.clear();
    this.#epoch += 1;
  }`,
    replacement: `advanceEpoch(): void {
    this.#epoch += 1;
  }`,
    target: unit("src/crypto/voprf.test.ts", "DV-13"),
  },
  {
    id: "DV-14",
    finding:
      "Blob identifiers must not be reused after collision-bucket deletion.",
    file: "src/model/storage.ts",
    anchor: "blobId: `blob-${this.#blobSequence}`",
    replacement: "blobId: `${index}:${bucket.length}`",
    target: unit("src/model/storage.test.ts", "DV-14"),
  },
  {
    id: "DV-15",
    finding: "A capsule must authenticate the complete data ciphertext.",
    file: "src/crypto/aes.ts",
    anchor: "    copyBytes(dataCiphertext),",
    replacement: "    new Uint8Array(),",
    target: unit("src/crypto/aes.test.ts", "DV-15"),
  },
  {
    id: "DV-16",
    finding: "VOPRF proof verification must use the client-pinned public key.",
    file: "src/crypto/voprf.ts",
    anchor: `    response.evaluated,
    blinded.blinded,
    pinnedPublicKey,
    response.proof,`,
    replacement: `    response.evaluated,
    blinded.blinded,
    server.publicKey(),
    response.proof,`,
    target: unit("src/crypto/voprf.test.ts", "DV-16"),
  },
  {
    id: "DV-17",
    finding:
      "Owner/reference tuple encoding must remain injective for arbitrary strings.",
    file: "src/model/storage.ts",
    anchor: "return JSON.stringify([owner, referenceId]);",
    replacement: "return `${owner}\\u0000${referenceId}`;",
    target: unit("src/model/storage.test.ts", "DV-17"),
  },
  {
    id: "DV-18",
    finding:
      "Dictionary decoys must match target length so length leakage cannot skip them.",
    file: "src/main.ts",
    anchor: '{ label: "same-length candidate B", file: secondDecoy },',
    replacement: '{ label: "short candidate", file: utf8("short") },',
    target: browser("DV-18"),
  },
  {
    id: "DV-19",
    finding: "A capsule must authenticate the construction version label.",
    file: "src/crypto/aes.ts",
    anchor: '    utf8("dedup-vault/capsule/v1"),',
    replacement: '    utf8("dedup-vault/capsule/v2"),',
    target: unit("src/crypto/aes.test.ts", "DV-19"),
  },
  {
    id: "DV-20",
    finding:
      "A possession response must commit to the fresh challenge nonce so an old response cannot be replayed.",
    file: "src/model/storage.ts",
    anchor: `  return domainHash(
    "dedup-vault/v1/whole-ciphertext-possession",
    nonce,
    completeCiphertext,
  );`,
    replacement: `  return domainHash(
    "dedup-vault/v1/whole-ciphertext-possession",
    completeCiphertext,
  );`,
    target: unit("src/model/storage.test.ts", "DV-20"),
  },
  {
    id: "DV-21",
    finding:
      "The learner UI must distinguish key-server-only and combined key-server-plus-ciphertext compromise views.",
    file: "src/main.ts",
    anchor: '      "Combined key-server and ciphertext compromise",',
    replacement: '      "Key-server compromise",',
    target: browser("DV-21"),
  },
];

function git(args) {
  const result = spawnSync("git", ["-C", ROOT, ...args], {
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${result.stderr}`);
  }
  return result.stdout;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function occurrences(text, anchor) {
  return text.split(anchor).length - 1;
}

function assertClean() {
  if (git(["rev-parse", "HEAD"]).trim() !== HEAD) {
    throw new Error("HEAD moved during the mutation run");
  }
  const status = git(["status", "--porcelain=v1", "--untracked-files=all"]);
  if (status !== "")
    throw new Error(`working tree is not clean: ${status.trim()}`);
}

function run(label, program, args, timeout = 300_000) {
  const startedAt = new Date().toISOString();
  const result = spawnSync(program, args, {
    cwd: ROOT,
    env: CHILD_ENV,
    encoding: "utf8",
    maxBuffer: 40 * 1024 * 1024,
    timeout,
  });
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  return {
    label,
    program,
    args,
    startedAt,
    finishedAt: new Date().toISOString(),
    status: result.status,
    signal: result.signal,
    error: result.error?.message,
    output,
  };
}

function mustPass(result) {
  if (result.status !== 0 || result.signal || result.error) {
    throw new Error(`${result.label} failed\n${result.output}`);
  }
}

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

function bundleDigest() {
  const directory = path.join(ROOT, "dist", "assets");
  const files = fs
    .readdirSync(directory)
    .filter((name) => name.endsWith(".js"))
    .sort();
  if (files.length === 0)
    throw new Error("build produced no JavaScript bundle");
  return sha256(
    files
      .map((name) => fs.readFileSync(path.join(directory, name)))
      .reduce(
        (joined, bytes) => Buffer.concat([joined, bytes]),
        Buffer.alloc(0),
      ),
  );
}

function build(label) {
  const result = run(label, "npm", ["run", "build"]);
  mustPass(result);
  return { command: result, digest: bundleDigest() };
}

function targetFailureIsOwned(result, id) {
  if (result.status === 0) return false;
  if (result.status !== 1 || result.signal || result.error) {
    throw new Error(
      `${id}: target did not end in an ordinary test failure\n${result.output}`,
    );
  }
  if (
    /browserType\.launch|Executable doesn't exist|ERR_CONNECTION|ECONNREFUSED|EADDRINUSE|Target page, context or browser has been closed|Test timeout/i.test(
      result.output,
    )
  ) {
    throw new Error(
      `${id}: infrastructure failure is not a caught mutation\n${result.output}`,
    );
  }
  if (
    !result.output.includes(id) ||
    !/AssertionError|expect\(|Expected:|Received:|Assertion/i.test(
      result.output,
    )
  ) {
    throw new Error(
      `${id}: failure was not owned by the named assertion\n${result.output}`,
    );
  }
  return true;
}

function compact(result) {
  return {
    label: result.label,
    program: result.program,
    args: result.args,
    startedAt: result.startedAt,
    finishedAt: result.finishedAt,
    status: result.status,
    signal: result.signal,
    error: result.error,
    outputSha256: sha256(result.output),
    outputTail: result.output.slice(-4000),
  };
}

function main() {
  if (process.argv.length !== 2) {
    throw new Error(
      "Usage: node scripts/claim-mutations.mjs (commit real work first)",
    );
  }
  if (
    fs.realpathSync(git(["rev-parse", "--show-toplevel"]).trim()) !==
    fs.realpathSync(ROOT)
  ) {
    throw new Error("run this script from its own repository");
  }
  assertClean();
  fs.mkdirSync(RESULT_ROOT, { recursive: true });
  const runDirectory = path.join(
    RESULT_ROOT,
    `${new Date().toISOString().replaceAll(/[:.]/g, "-")}-${process.pid}`,
  );
  fs.mkdirSync(runDirectory);
  const report = {
    schemaVersion: 1,
    head: HEAD,
    startedAt: new Date().toISOString(),
    baseline: {},
    mutations: [],
    status: "RUNNING",
  };
  const save = () => {
    fs.mkdirSync(runDirectory, { recursive: true });
    fs.writeFileSync(
      path.join(runDirectory, "report.json"),
      `${JSON.stringify(report, null, 2)}\n`,
    );
  };

  for (const mutation of MUTATIONS) {
    const bytes = fs.readFileSync(path.join(ROOT, mutation.file));
    const text = bytes.toString("utf8");
    if (
      occurrences(text, mutation.anchor) !== 1 ||
      mutation.anchor === mutation.replacement
    ) {
      throw new Error(
        `${mutation.id}: anchor must occur exactly once in ${mutation.file}`,
      );
    }
    const committed = git(["show", `HEAD:${mutation.file}`]);
    if (!Buffer.from(committed).equals(bytes)) {
      throw new Error(`${mutation.file} differs from the committed baseline`);
    }
  }

  try {
    const baselineBuild = build("baseline build");
    const baselineUnit = run("baseline unit", "npm", ["test"]);
    mustPass(baselineUnit);
    const baselineBrowser = run(
      "baseline browser claims",
      "npm",
      ["run", "test:claims"],
      600_000,
    );
    mustPass(baselineBrowser);
    assertClean();
    report.baseline = {
      bundleSha256: baselineBuild.digest,
      build: compact(baselineBuild.command),
      unit: compact(baselineUnit),
      browser: compact(baselineBrowser),
      passed: true,
    };
    console.info("baseline: unmutated copy PASSES");
    save();

    for (const mutation of MUTATIONS) {
      const targetPath = path.join(ROOT, mutation.file);
      const original = fs.readFileSync(targetPath);
      const changed = Buffer.from(
        original
          .toString("utf8")
          .replace(mutation.anchor, mutation.replacement),
      );
      const evidence = {
        id: mutation.id,
        finding: mutation.finding,
        file: mutation.file,
        originalSha256: sha256(original),
        mutantSha256: sha256(changed),
        status: "RUNNING",
      };
      report.mutations.push(evidence);
      save();
      let mutationError;
      let restorationError;
      try {
        fs.writeFileSync(targetPath, changed);
        const dirty = git([
          "status",
          "--porcelain=v1",
          "--untracked-files=all",
        ]);
        if (dirty !== ` M ${mutation.file}\n`) {
          throw new Error(
            `${mutation.id}: mutation did not produce exactly one modified file: ${dirty}`,
          );
        }
        const mutantBuild = build(`${mutation.id} mutant build`);
        if (mutantBuild.digest === report.baseline.bundleSha256) {
          throw new Error(
            `${mutation.id}: source mutation did not change the browser bundle`,
          );
        }
        const result = run(
          `${mutation.id} owning test`,
          mutation.target.program,
          mutation.target.args,
          mutation.target.program === "npx" &&
            mutation.target.args.includes("playwright")
            ? 600_000
            : 300_000,
        );
        requireCondition(
          targetFailureIsOwned(result, mutation.id),
          `${mutation.id}: mutant survived its owning assertion`,
        );
        evidence.mutantBundleSha256 = mutantBuild.digest;
        evidence.build = compact(mutantBuild.command);
        evidence.owningTest = compact(result);
      } catch (error) {
        mutationError = error;
        evidence.error = error.message;
      } finally {
        try {
          fs.writeFileSync(targetPath, original);
          requireCondition(
            fs.readFileSync(targetPath).equals(original),
            `${mutation.id}: exact source restoration failed`,
          );
          const restoredBuild = build(`${mutation.id} restored build`);
          requireCondition(
            restoredBuild.digest === report.baseline.bundleSha256,
            `${mutation.id}: restored bundle differs from baseline`,
          );
          const restoredTarget = run(
            `${mutation.id} restored owning test`,
            mutation.target.program,
            mutation.target.args,
            mutation.target.program === "npx" &&
              mutation.target.args.includes("playwright")
              ? 600_000
              : 300_000,
          );
          mustPass(restoredTarget);
          assertClean();
          evidence.restoration = {
            sourceSha256: sha256(fs.readFileSync(targetPath)),
            bundleSha256: restoredBuild.digest,
            build: compact(restoredBuild.command),
            owningTest: compact(restoredTarget),
            passed: true,
          };
        } catch (error) {
          restorationError = error;
          evidence.restoration = { passed: false, error: error.message };
        }
      }
      if (restorationError) throw restorationError;
      if (mutationError) {
        evidence.status = "FAILED";
        save();
        throw mutationError;
      }
      evidence.status = "CAUGHT";
      console.info(`${mutation.id}: caught`);
      save();
    }

    report.status = "PASSED";
    report.finishedAt = new Date().toISOString();
    save();
    console.info(`all ${MUTATIONS.length} mutation(s) caught`);
    console.info(`evidence: ${path.join(runDirectory, "report.json")}`);
  } catch (error) {
    report.status = "FAILED";
    report.finishedAt = new Date().toISOString();
    report.error = error.message;
    save();
    console.error(`mutation gate FAILED: ${error.message}`);
    console.error(`evidence: ${path.join(runDirectory, "report.json")}`);
    process.exitCode = 1;
  }
}

main();
