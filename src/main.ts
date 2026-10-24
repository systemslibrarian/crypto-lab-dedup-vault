import "./style.css";

import {
  compromisedServerDictionaryAttack,
  offlineDictionaryAttack,
  onlineServerDictionaryAttack,
  type DictionaryCandidate,
  type DictionaryResult,
} from "./attacks/dictionary";
import { deriveLocalDataKey, encryptData } from "./crypto/aes";
import { bytesToHex, flipByte, utf8 } from "./crypto/bytes";
import {
  deriveServerDataKey,
  finalizeVoprfTranscript,
  VoprfKeyServer,
} from "./crypto/voprf";
import {
  runBoundaryDemonstration,
  type BoundaryEvidence,
} from "./model/boundaries";
import {
  runComparison,
  type ComparisonEvidence,
  type DedupMode,
} from "./model/scenario";

const DEFAULT_FILE = "Campus payroll closes Friday at 17:00.";
const app = document.querySelector<HTMLDivElement>("#app");
if (!app) throw new Error("application root is missing");

app.innerHTML = `
  <main id="main-content" tabindex="-1">
    <header class="hero">
      <p class="eyebrow">Applied cryptography · A-D-01</p>
      <h1>Dedup Vault</h1>
      <p class="lede">When equal plaintexts should occupy one encrypted blob, what equality leaks—and who can test guesses?</p>
      <div class="scope-banner">
        <strong>Bounded teaching model.</strong> This browser lab uses real AES-128-CTR, AES-SIV-CMAC-256 (two AES-128 subkeys), SHA-256, and RFC 9497 P256-SHA256 VOPRF computations. It is not a production storage design.
      </div>
    </header>

    <section class="exhibit" aria-labelledby="exhibit-1-heading">
      <p class="exhibit-number">Exhibit 1</p>
      <h2 id="exhibit-1-heading">Equal file, three encryption choices</h2>
      <p>Upload the exact same bytes as Alice and Bob. Fresh random keys hide ciphertext-byte equality but do not hide length or metadata, and they do not deduplicate. Deterministic local or server-aided derivation makes equal files produce equal data ciphertext, while each owner keeps a distinct authenticated key capsule.</p>
      <form id="comparison-form" class="control-panel">
        <label for="file-input">Synthetic file contents</label>
        <textarea id="file-input" rows="3" maxlength="512">${DEFAULT_FILE}</textarea>
        <div class="control-row">
          <button id="run-button" type="submit">Run all experiments</button>
          <span id="run-status" role="status" aria-live="polite" aria-atomic="true"></span>
        </div>
      </form>
      <div id="comparison-output" class="output" data-stale="true"></div>
    </section>

    <section class="exhibit" aria-labelledby="exhibit-2-heading">
      <p class="exhibit-number">Exhibit 2</p>
      <h2 id="exhibit-2-heading">Dictionary pressure and the online boundary</h2>
      <p>Deterministic ciphertext is a confirmation oracle for low-entropy files. A key server moves each guess online. This model accepts only allowlisted principal labels, standing in for an external authentication decision, and applies a per-principal epoch budget—but identities, later epochs, or server compromise change that boundary.</p>
      <div id="attack-output" class="output" data-stale="true"></div>
    </section>

    <section class="exhibit" aria-labelledby="exhibit-3-heading">
      <p class="exhibit-number">Exhibit 3</p>
      <h2 id="exhibit-3-heading">Who learns what?</h2>
      <div id="roles-output" class="role-grid output" data-stale="true"></div>
    </section>

    <section class="exhibit" aria-labelledby="exhibit-4-heading">
      <p class="exhibit-number">Exhibit 4</p>
      <h2 id="exhibit-4-heading">Boundaries: possession, authorization, deletion, revocation, rotation</h2>
      <p>A possession response is not an authorization grant. Reference counts determine deletion. Revocation blocks future modeled reads and derivations, not copies already cached. Rotating the VOPRF key changes future derivation but does not rewrite old ciphertext.</p>
      <div id="boundary-output" class="output" data-stale="true"></div>
    </section>

    <section class="exhibit" aria-labelledby="exhibit-5-heading">
      <p class="exhibit-number">Exhibit 5</p>
      <h2 id="exhibit-5-heading">Construction, adaptation, and limits</h2>
      <div class="limitations">
        <h3>What is implemented</h3>
        <ul>
          <li><strong>Local MLE:</strong> first 128 bits of SHA-256(<var>P</var> ∥ <var>M</var>), following DupLESS’s convergent-encryption formula but using a fixed lesson-specific 128-bit public parameter instead of a randomly sampled setup parameter.</li>
          <li><strong>Server-aided mode:</strong> a modern adaptation using RFC 9497 verifiable OPRF mode with the P256-SHA256 suite. The client verifies the DLEQ proof against a pinned public key before accepting output; authentic provisioning of that key is outside this model.</li>
          <li><strong>Data:</strong> AES-128-CTR with a fixed counter in the DupLESS-shaped deterministic model. Repeat encryption of the same value deliberately repeats key and counter to reveal equality, departing from ordinary CTR counter-uniqueness; using that pair for any different plaintext exposes the plaintext XOR.</li>
          <li><strong>Capsules:</strong> per-user AES-SIV-CMAC-256 wrapping (a 32-byte combined key containing two AES-128 subkeys), authenticated to the owner, reference, and complete data ciphertext.</li>
        </ul>
        <h3>What is not established</h3>
        <ul>
          <li>This is not the exact DupLESS construction: it replaces the blind-RSA OPRF with a P-256 VOPRF, replaces DupLESS’s HMAC-SHA256/AES-CTR SIV capsule with RFC 5297 AES-CMAC-SIV, and omits its path/name handling. The original proof does not transfer automatically.</li>
          <li>The browser places client, key server, storage server, and attacker simulations in one origin; the role separation is pedagogical, not an isolation boundary.</li>
          <li>The nonce challenge returns a short hash but makes both sides read the complete modeled ciphertext. It is a bounded counterexample to “a short identifier proves possession,” not the paper’s formal, leakage-resilient, scalable proof-of-ownership construction.</li>
          <li>Rate limits delay dictionary search; they do not make low-entropy plaintext secret. Multiple accounts, epochs, or key-server compromise can expand the budget.</li>
          <li>Revocation cannot erase a plaintext, key, or ciphertext an authorized client already cached.</li>
          <li>A capsule detects unauthenticated byte changes, but without trusted version state it does not detect rollback or replay of an older valid <var>Cdata</var>/capsule pair.</li>
          <li>JavaScript does not promise constant-time execution. <a href="https://github.com/paulmillr/noble-curves/blob/main/README.md#security">Noble Curves’ security record</a> covers version 2.3.0, while this lesson pins 2.4.0. <a href="https://github.com/paulmillr/noble-ciphers/blob/main/README.md#security">Noble Ciphers’ security record</a> covers version 1.0.0; <a href="https://github.com/paulmillr/noble-ciphers/releases/tag/2.1.1">AES-SIV entered in 2.1.1</a>, so the exact AES-SIV code used here postdates that independent audit.</li>
        </ul>
      </div>
      <details>
        <summary>Primary sources and exact standards</summary>
        <ul>
          <li><a href="https://eprint.iacr.org/2012/631">Bellare, Keelveedhi, and Ristenpart, Message-Locked Encryption and Secure Deduplication (EUROCRYPT 2013)</a></li>
          <li><a href="https://www.usenix.org/conference/usenixsecurity13/technical-sessions/presentation/bellare">Bellare et al., DupLESS: Server-Aided Encryption for Deduplicated Storage (USENIX Security 2013)</a></li>
          <li><a href="https://www.rfc-editor.org/rfc/rfc9497">RFC 9497, Oblivious Pseudorandom Functions</a></li>
          <li><a href="https://www.rfc-editor.org/rfc/rfc5297">RFC 5297, Synthetic Initialization Vector authenticated encryption</a></li>
          <li><a href="https://csrc.nist.gov/pubs/sp/800/38/a/final">NIST SP 800-38A, confidentiality modes including CTR</a></li>
          <li><a href="https://eprint.iacr.org/2011/207">Halevi et al., Proofs of Ownership in Remote Storage Systems</a></li>
        </ul>
      </details>
      <nav class="related-labs" aria-label="Related Crypto Lab lessons">
        <h3>Continue with related labs</h3>
        <ul>
          <li><a href="https://systemslibrarian.github.io/crypto-lab-envelope-kms/">Envelope KMS</a> — compare randomized envelope encryption, wrapping, rewrapping, and compromise scope.</li>
          <li><a href="https://systemslibrarian.github.io/crypto-lab-opaque-gate/">OPAQUE Gate</a> — inspect a password-authentication protocol with a distinct OPRF role and threat model.</li>
          <li><a href="https://systemslibrarian.github.io/crypto-lab-oram-vault/">ORAM Vault</a> — examine access-pattern leakage that ciphertext confidentiality alone does not hide.</li>
        </ul>
      </nav>
    </section>
  </main>
  <footer>
    <p>All files and guesses in this lesson are synthetic and computed locally. Inspect the source and tests for every displayed claim.</p>
  </footer>
`;

function requiredElement<T extends Element>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (!element)
    throw new Error(`required application element is missing: ${selector}`);
  return element;
}

const input = requiredElement<HTMLTextAreaElement>("#file-input");
const form = requiredElement<HTMLFormElement>("#comparison-form");
const status = requiredElement<HTMLSpanElement>("#run-status");
const comparisonOutput = requiredElement<HTMLDivElement>("#comparison-output");
const attackOutput = requiredElement<HTMLDivElement>("#attack-output");
const rolesOutput = requiredElement<HTMLDivElement>("#roles-output");
const boundaryOutput = requiredElement<HTMLDivElement>("#boundary-output");

const outputs = [comparisonOutput, attackOutput, rolesOutput, boundaryOutput];

function shortHex(value: Uint8Array, bytes = 12): string {
  const complete = bytesToHex(value);
  return value.length > bytes ? `${complete.slice(0, bytes * 2)}…` : complete;
}

function setCode(cell: HTMLTableCellElement, value: Uint8Array): void {
  const code = document.createElement("code");
  code.textContent = shortHex(value);
  code.dataset.hex = bytesToHex(value);
  code.title = `${value.length} bytes: ${bytesToHex(value)}`;
  cell.append(code);
}

function comparisonTable(evidence: ComparisonEvidence): HTMLTableElement {
  const table = document.createElement("table");
  table.id = "mode-comparison";
  table.innerHTML = `
    <caption>Measured result for two uploads of the same ${evidence.file.length}-byte file. Counted payload total = unique Cdata + capsules; it excludes identifiers, indexes, allocator overhead, and protocol traffic.</caption>
    <thead><tr><th scope="col">Mode</th><th scope="col">Alice / Bob key</th><th scope="col">Data ciphertext</th><th scope="col">Unique blobs</th><th scope="col">Logical data</th><th scope="col">Unique Cdata</th><th scope="col">Capsules</th><th scope="col">Counted payload total</th><th scope="col">Data dedup ratio</th></tr></thead>
    <tbody></tbody>
  `;
  const labels: Record<DedupMode, string> = {
    fresh: "Fresh random key",
    "local-mle": "Local MLE",
    "server-aided": "Server-aided VOPRF",
  };
  const body = table.tBodies[0];
  for (const mode of ["fresh", "local-mle", "server-aided"] as const) {
    const result = evidence.modes[mode];
    const row = body.insertRow();
    row.dataset.mode = mode;
    const heading = document.createElement("th");
    heading.scope = "row";
    heading.textContent = labels[mode];
    row.append(heading);
    const keys = row.insertCell();
    setCode(keys, result.uploads[0].dataKey);
    keys.append(document.createTextNode(" / "));
    setCode(keys, result.uploads[1].dataKey);
    keys.dataset.equal = String(
      bytesToHex(result.uploads[0].dataKey) ===
        bytesToHex(result.uploads[1].dataKey),
    );
    const ciphertext = row.insertCell();
    setCode(ciphertext, result.uploads[0].dataCiphertext);
    ciphertext.append(document.createTextNode(" / "));
    setCode(ciphertext, result.uploads[1].dataCiphertext);
    ciphertext.dataset.equal = String(result.equalDataCiphertexts);
    ciphertext.append(
      document.createTextNode(
        result.equalDataCiphertexts ? " = equal" : " ≠ different",
      ),
    );
    const blobs = row.insertCell();
    blobs.textContent = String(result.uniqueBlobs);
    blobs.dataset.value = String(result.uniqueBlobs);
    const logical = row.insertCell();
    logical.textContent = `${result.logicalDataBytes} B`;
    logical.dataset.value = String(result.logicalDataBytes);
    const uniqueData = row.insertCell();
    uniqueData.textContent = `${result.uniqueDataBytes} B`;
    uniqueData.dataset.value = String(result.uniqueDataBytes);
    const capsules = row.insertCell();
    const capsuleSummary = document.createElement("span");
    capsuleSummary.textContent = `${result.references} × ${result.uploads[0].capsule.length} B; distinct: ${result.distinctCapsules ? "yes" : "no"}. `;
    capsules.append(capsuleSummary);
    setCode(capsules, result.uploads[0].capsule);
    capsules.append(document.createTextNode(" / "));
    setCode(capsules, result.uploads[1].capsule);
    capsules.dataset.bytes = String(result.capsuleBytes);
    capsules.dataset.distinct = String(result.distinctCapsules);
    const total = row.insertCell();
    total.textContent = `${result.totalStoredBytes} B`;
    total.dataset.value = String(result.totalStoredBytes);
    const ratio = row.insertCell();
    ratio.textContent = `${result.dataDedupRatio.toFixed(2)}×`;
    ratio.dataset.value = String(result.dataDedupRatio);
  }
  return table;
}

type AttackEvidence = {
  localHit: DictionaryResult;
  localMiss: DictionaryResult;
  onlineHit: DictionaryResult;
  limited: DictionaryResult;
  rejectedPrincipal: DictionaryResult;
  firstIdentity: DictionaryResult;
  secondIdentity: DictionaryResult;
  nextEpoch: DictionaryResult;
  compromised: DictionaryResult;
  proofTamperRejected: boolean;
  candidateByteLength: number;
  candidateLengthsEqual: boolean;
};

function candidates(file: Uint8Array): DictionaryCandidate[] {
  const firstDecoy = file.slice();
  const secondDecoy = file.slice();
  firstDecoy[0] ^= 0x01;
  secondDecoy[0] ^= 0x02;
  return [
    { label: "same-length candidate A", file: firstDecoy },
    { label: "same-length candidate B", file: secondDecoy },
    { label: "the selected file", file },
  ];
}

function runAttacks(file: Uint8Array): AttackEvidence {
  const guesses = candidates(file);
  const localTarget = encryptData(deriveLocalDataKey(file), file);
  const localHit = offlineDictionaryAttack(localTarget, guesses);
  const localMiss = offlineDictionaryAttack(localTarget, guesses.slice(0, 2));

  const hitServer = new VoprfKeyServer({ limit: 3, authorized: ["mallory"] });
  const finalTarget = encryptData(
    hitServer.compromisedEvaluate(file).slice(0, 16),
    file,
  );
  const onlineHit = onlineServerDictionaryAttack(
    finalTarget,
    guesses,
    hitServer,
    "mallory",
  );

  const limitedServer = new VoprfKeyServer({
    limit: 2,
    authorized: ["mallory"],
  });
  const limitedKey = limitedServer.compromisedEvaluate(file).slice(0, 16);
  const limitedTarget = encryptData(limitedKey, file);
  const limited = onlineServerDictionaryAttack(
    limitedTarget,
    guesses,
    limitedServer,
    "mallory",
  );
  const rejectedPrincipal = onlineServerDictionaryAttack(
    limitedTarget,
    guesses,
    limitedServer,
    "eve",
  );

  const identityServer = new VoprfKeyServer({
    limit: 2,
    authorized: ["mallory-1", "mallory-2"],
  });
  const identityTarget = encryptData(
    identityServer.compromisedEvaluate(file).slice(0, 16),
    file,
  );
  const firstIdentity = onlineServerDictionaryAttack(
    identityTarget,
    guesses,
    identityServer,
    "mallory-1",
  );
  const secondIdentity = onlineServerDictionaryAttack(
    identityTarget,
    [guesses[2]],
    identityServer,
    "mallory-2",
  );
  const epochServer = new VoprfKeyServer({ limit: 2, authorized: ["mallory"] });
  const epochTarget = encryptData(
    epochServer.compromisedEvaluate(file).slice(0, 16),
    file,
  );
  onlineServerDictionaryAttack(epochTarget, guesses, epochServer, "mallory");
  epochServer.advanceEpoch();
  const nextEpoch = onlineServerDictionaryAttack(
    epochTarget,
    [guesses[2]],
    epochServer,
    "mallory",
  );
  const compromised = compromisedServerDictionaryAttack(
    limitedTarget,
    guesses,
    limitedServer,
  );

  const proofServer = new VoprfKeyServer({ limit: 1, authorized: ["mallory"] });
  const proof = deriveServerDataKey(
    file,
    proofServer,
    "mallory",
    proofServer.publicKey(),
  );
  if (proof.status !== "ok") throw new Error("proof setup unexpectedly failed");
  let proofTamperRejected = false;
  try {
    finalizeVoprfTranscript(proof.transcript, flipByte(proof.transcript.proof));
  } catch {
    proofTamperRejected = true;
  }

  return {
    localHit,
    localMiss,
    onlineHit,
    limited,
    rejectedPrincipal,
    firstIdentity,
    secondIdentity,
    nextEpoch,
    compromised,
    proofTamperRejected,
    candidateByteLength: file.length,
    candidateLengthsEqual: guesses.every(
      (candidate) => candidate.file.length === file.length,
    ),
  };
}

function attackCard(
  title: string,
  result: DictionaryResult,
  claim: string,
): HTMLElement {
  const article = document.createElement("article");
  article.className = "result-card";
  article.dataset.outcome = result.outcome;
  article.innerHTML = `<h3></h3><p class="outcome"></p><p class="claim"></p><p class="note"></p>`;
  const [heading, outcome, claimNode, note] = article.querySelectorAll("h3, p");
  heading.textContent = title;
  outcome.textContent = `Outcome: ${result.outcome}; completed comparisons: ${result.attempted}${result.match ? `; match: ${result.match.label}` : ""}.`;
  claimNode.textContent = claim;
  note.textContent = result.note;
  return article;
}

function renderAttacks(evidence: AttackEvidence): void {
  attackOutput.replaceChildren();
  const lengthControl = document.createElement("p");
  lengthControl.className = "length-control";
  lengthControl.dataset.equal = String(evidence.candidateLengthsEqual);
  lengthControl.textContent = `Length control: the target and every candidate are ${evidence.candidateByteLength} bytes, so ciphertext length cannot eliminate either decoy for free.`;
  attackOutput.append(lengthControl);
  const grid = document.createElement("div");
  grid.className = "result-grid";
  grid.append(
    attackCard(
      "Local MLE: target in dictionary",
      evidence.localHit,
      "Offline guesses need no server.",
    ),
    attackCard(
      "Local MLE: target absent",
      evidence.localMiss,
      "No match is not proof of high entropy.",
    ),
    attackCard(
      "Server-aided: within q = 3",
      evidence.onlineHit,
      "The third allowed query succeeds.",
    ),
    attackCard(
      "Server-aided: beyond q = 2",
      evidence.limited,
      "The third guess is delayed by the epoch budget.",
    ),
    attackCard(
      "Unknown identity",
      evidence.rejectedPrincipal,
      "The modeled principal allowlist is checked before evaluation or counting; this is not an authentication protocol.",
    ),
    attackCard(
      "First allowlisted principal",
      evidence.firstIdentity,
      "One identity exhausts its two-query budget.",
    ),
    attackCard(
      "Second allowlisted principal",
      evidence.secondIdentity,
      "Another authorized identity has a separate budget.",
    ),
    attackCard(
      "Next rate epoch",
      evidence.nextEpoch,
      "A new budget under the same VOPRF key can confirm another guess.",
    ),
    attackCard(
      "Key server compromised",
      evidence.compromised,
      "Compromise removes the online query boundary.",
    ),
  );
  attackOutput.append(grid);
  const proof = document.createElement("p");
  proof.className = "proof-result";
  proof.dataset.rejected = String(evidence.proofTamperRejected);
  proof.textContent = evidence.proofTamperRejected
    ? "Verified: changing one VOPRF proof byte is rejected."
    : "Failure: the changed VOPRF proof was accepted.";
  attackOutput.append(proof);
}

function renderRoles(evidence: ComparisonEvidence): void {
  rolesOutput.replaceChildren();
  const serverUpload = evidence.modes["server-aided"].uploads[0];
  const cards = [
    [
      "Client",
      `Starts with ${evidence.file.length} plaintext bytes; blinds a 32-byte derived input; receives and verifies a ${serverUpload.voprf?.proof.length ?? 0}-byte DLEQ proof; keeps its wrapping key.`,
    ],
    [
      "Key server",
      `Sees an allowlisted principal label (standing in for external authentication) plus ${serverUpload.voprf?.blinded.length ?? 0}-byte blinded and ${serverUpload.voprf?.evaluated.length ?? 0}-byte evaluated elements. This view receives neither plaintext nor stored target ciphertext, so it lacks the equality target needed to confirm a guess.`,
    ],
    [
      "Storage server",
      `Sees deterministic data ciphertext, equality across owners, blob index, owner/reference metadata, and distinct ${serverUpload.capsule.length}-byte capsules.`,
    ],
    [
      "Storage-only attacker",
      "Can group equal ciphertext and test local-MLE guesses, but cannot perform server-aided guesses without VOPRF evaluations.",
    ],
    [
      "Allowlisted guessing client",
      "With copied target ciphertext, can submit blinded candidates and confirm equality, but receives only the displayed per-principal, per-epoch request budget.",
    ],
    [
      "Combined key-server and ciphertext compromise",
      "Can evaluate the VOPRF offline; with access to copied or stored target ciphertext, deterministic equality then confirms candidate plaintexts.",
    ],
  ];
  for (const [title, body] of cards) {
    const article = document.createElement("article");
    article.innerHTML = "<h3></h3><p></p>";
    article.querySelector("h3")!.textContent = title;
    article.querySelector("p")!.textContent = body;
    rolesOutput.append(article);
  }
}

function boundaryItem(
  label: string,
  passed: boolean,
  detail: string,
): HTMLLIElement {
  const item = document.createElement("li");
  item.dataset.passed = String(passed);
  item.innerHTML = "<strong></strong><span></span>";
  item.querySelector("strong")!.textContent =
    `${passed ? "PASS" : "FAIL"} — ${label}`;
  item.querySelector("span")!.textContent = detail;
  return item;
}

function renderBoundaries(result: BoundaryEvidence): void {
  const list = document.createElement("ul");
  list.className = "boundary-list";
  list.append(
    boundaryItem(
      "Identifier alone is rejected",
      result.possession.blobIdOnlyRejected,
      "The response must commit to the nonce and complete ciphertext.",
    ),
    boundaryItem(
      "Complete ciphertext is accepted once",
      result.possession.completeCiphertextAccepted &&
        result.possession.replayRejected,
      "The nonce challenge is consumed, so replay fails.",
    ),
    boundaryItem(
      "Possession does not grant a reference",
      !result.possession.referenceGranted,
      "Mallory still fails the authorization check.",
    ),
    boundaryItem(
      "Owner isolation",
      result.authorization.ownerReadAccepted &&
        result.authorization.crossOwnerReadRejected,
      "Alice reads Alice’s reference; Mallory cannot.",
    ),
    boundaryItem(
      "First deletion retains shared blob",
      !result.deletion.firstReferenceDeletedBlob &&
        result.deletion.afterFirstReferences === 1,
      "Bob’s remaining reference keeps one blob.",
    ),
    boundaryItem(
      "Last deletion removes blob",
      result.deletion.lastReferenceDeletedBlob &&
        result.deletion.afterLastBlobs === 0,
      "Zero references removes the ciphertext.",
    ),
    boundaryItem(
      "Revocation is prospective",
      result.revocation.futureStorageReadRejected &&
        result.revocation.futureVoprfRejected &&
        result.revocation.cachedCopyStillOpened,
      "Future modeled reads and derivations are denied; a cached authorized copy still opens.",
    ),
    boundaryItem(
      "Rotation changes future derivation",
      result.rotation.publicKeyChanged &&
        result.rotation.dataKeyChanged &&
        result.rotation.ciphertextChanged &&
        result.rotation.oldCapsuleStillOpened,
      "New key material changes; the old capsule still opens its old data key.",
    ),
    boundaryItem(
      "VOPRF proof tamper is rejected",
      result.proofTamperRejected,
      "One changed proof byte fails verification.",
    ),
  );
  boundaryOutput.replaceChildren(list);
}

function markStale(): void {
  for (const output of outputs) output.dataset.stale = "true";
  status.textContent =
    "Inputs changed. Displayed evidence is stale; run again.";
}

function run(): void {
  const file = utf8(input.value);
  if (file.length === 0) {
    status.textContent = "Enter at least one character.";
    return;
  }
  const comparison = runComparison(file);
  const attacks = runAttacks(file);
  const boundaries = runBoundaryDemonstration(file);
  comparisonOutput.replaceChildren(comparisonTable(comparison));
  renderAttacks(attacks);
  renderRoles(comparison);
  renderBoundaries(boundaries);
  for (const output of outputs) output.dataset.stale = "false";
  status.textContent = `Fresh evidence computed for ${file.length} UTF-8 bytes.`;
}

input.addEventListener("input", markStale);
form.addEventListener("submit", (event) => {
  event.preventDefault();
  run();
});

run();
