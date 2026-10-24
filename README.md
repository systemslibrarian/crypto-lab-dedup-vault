# Dedup Vault

Dedup Vault is an executable lesson about encrypted deduplication, message-locked encryption (MLE), and server-aided derivation. Two synthetic users upload the same bytes in three modes, and the page measures which encrypted objects become equal, what storage is saved, and when a dictionary attacker can confirm a guess.

Live lesson: <https://systemslibrarian.github.io/crypto-lab-dedup-vault/>

## What the lesson computes

The page runs every result in the browser from the TypeScript implementation in `src/`; it does not substitute hardcoded attack outcomes or storage totals.

### 1. Fresh per-upload encryption

Each upload draws a new 128-bit data key and encrypts its file with AES-128-CTR. The counter is the all-zero 128-bit value and each independently random key is used for one message. Equal plaintext uploads therefore normally have unequal data ciphertexts and occupy two content objects.

This is the no-deduplication comparison. It is not authenticated data encryption, and the demo does not recommend this construction as a production envelope format.

### 2. Local message-locked encryption

The local mode follows the concrete convergent-encryption formula described in DupLESS, with one setup adaptation:

```text
data_key = first128(SHA-256(P || file))
Cdata    = AES-128-CTR(data_key, counter = 0, file)
```

DupLESS samples `P` as a random 128-bit public setup parameter. This lab instead fixes `P` to a reproducible, lesson-specific 16-byte application value in `src/crypto/aes.ts`. It separates this lesson's key space; it is not a password, salt, or defense against a dictionary attack. Equal files produce equal keys and equal `Cdata`, so a storage observer learns equality and an attacker can test low-entropy candidates offline.

### 3. Server-aided derivation

The server-aided mode first computes a length-framed SHA-256 input over the scheme label, `P`, and the entire file. It then runs RFC 9497 VOPRF mode with the P256-SHA256 suite:

```text
input    = SHA-256(frame("dedup-vault/v1/voprf-input", P, file))
output   = VOPRF.Finalize(input, blind, evaluated, blinded, public_key, proof)
data_key = first128(output)
Cdata    = AES-128-CTR(data_key, counter = 0, file)
```

The client pins a public key before its request sequence and verifies the DLEQ proof against that key during `Finalize`; a changed proof, evaluated element, or coherent response under a substitute key is rejected. The proof establishes consistency with the pinned key, not that the key is authentic. Authentic public-key provisioning is outside the model. The modeled key server accepts only an allowlisted principal label before evaluation and allows exactly `q` successful requests per principal and epoch. That label represents the result of an external authentication step; this lab does not implement an authentication protocol.

This is a modern P-256 VOPRF adaptation of the server-aided idea in DupLESS. DupLESS used a blind-RSA OPRF, so the original proof does not automatically establish this substituted construction. The model demonstrates the boundary: rate limiting can delay a dictionary search, but additional identities, later epochs, collusion, or key-server compromise expand or remove that online boundary.

### Per-user key capsules

Each user has a distinct wrapping key, and each reference has a distinct capsule. The 16-byte data key is wrapped with RFC 5297 AES-SIV-CMAC-256 under a 32-byte combined key containing two AES-128 subkeys. This is another explicit adaptation: DupLESS §6 uses an HMAC-SHA256/AES-CTR SIV construction, produces a 384-bit `Ckey`, and includes path/name handling that this lesson omits. Four associated-data components here bind the capsule to:

1. the capsule scheme and version;
2. the owner identity;
3. the reference identifier; and
4. the complete data ciphertext.

Changing any bound value, the capsule, or the wrapping key makes opening fail. Owner and reference strings must be well-formed Unicode so UTF-8 encoding cannot merge distinct JavaScript strings through replacement-character substitution. The storage layer deduplicates `Cdata` only after complete byte equality; its SHA-256 index only selects a candidate bucket. A test injects an index collision and proves unequal ciphertexts remain separate.

The displayed “stored bytes” deliberately counts unique data-ciphertext bytes plus capsule bytes. It excludes object indexes, owner/reference strings, maps, allocator overhead, and protocol traffic. Both logical data bytes and the narrower physical-data ratio remain visible so capsule overhead is not silently presented as saved data.

## Five exhibits

1. **Equal file, three choices** compares actual keys, ciphertext equality, object counts, capsules, bytes, and the data-deduplication ratio.
2. **Dictionary pressure** computes a local offline hit and miss, server-aided guesses inside and beyond `q`, a principal absent from the modeled allowlist, separate principal budgets, a later rate epoch, key-server compromise, and proof tampering.
3. **Who learns what** separates client, key-server, storage-server, storage-only-attacker, allowlisted guessing-client, and combined key-server-plus-ciphertext-compromise views.
4. **Lifecycle boundaries** executes possession, authorization, replay, reference-count deletion, prospective revocation, and key rotation.
5. **Construction and limits** keeps the adaptation, primitive choices, primary sources, and nonclaims visible.

The possession exercise uses a fresh nonce and a short hash response over that nonce and the complete modeled ciphertext. It saves retransmitting the object, but both sides read the whole object. It shows why a blob identifier alone is not possession and why possession is not authorization; it is not the formal, leakage-resilient, scalable proof-of-ownership construction of Halevi, Harnik, Pinkas, and Shulman-Peleg.

## Security scope

This is a bounded teaching model, not production storage software.

- All roles execute in one browser origin. The UI does not establish process, network, hardware, or secret isolation.
- Deterministic data ciphertext leaks file equality, length, upload timing, and reference/deletion patterns to storage.
- Low-entropy files remain guessable. A per-principal request budget delays guesses; it does not create entropy or solve Sybil, distributed, eventual, or compromise attacks.
- The deterministic modes deliberately repeat an AES-CTR key and counter when the exact same plaintext value is repeated, exposing the equality needed for deduplication and departing from ordinary CTR counter-uniqueness. The model intends each derived key for only one distinct plaintext value; using that key/counter pair for any different plaintext exposes the plaintext XOR.
- The data ciphertext has no independent authentication tag. The authenticated per-user capsule commits to the complete ciphertext, so an authorized client detects changes when opening the capsule; this is not a general multi-writer storage design.
- The capsule detects unauthenticated byte changes, but without trusted external version state it does not detect rollback or replay of an older valid `(Cdata, capsule)` pair.
- Revocation blocks future modeled storage reads and VOPRF derivations. It cannot erase plaintext, ciphertext, or keys already cached by a formerly authorized client.
- Rotation changes future VOPRF output and ciphertext. It neither rewrites nor revokes old objects.
- JavaScript execution is not guaranteed constant-time.
- [Noble Curves' security record](https://github.com/paulmillr/noble-curves/blob/main/README.md#security) identifies an all-scope Trail of Bits review of version 2.3.0; this lesson pins the later [2.4.0 release](https://github.com/paulmillr/noble-curves/releases/tag/2.4.0). [Noble Ciphers' security record](https://github.com/paulmillr/noble-ciphers/blob/main/README.md#security) identifies an all-scope Cure53 review of version 1.0.0, while [AES-SIV was introduced in version 2.1.1](https://github.com/paulmillr/noble-ciphers/releases/tag/2.1.1). Upstream vector and self-audit evidence is useful, but this exact AES-SIV code is not covered by that independent audit.

See [SECURITY.md](SECURITY.md) and [docs/a-d-01-brief.md](docs/a-d-01-brief.md) for the threat model and acceptance mapping.

## Verification anchors

The unit suite checks:

- RFC 9497 Appendix A.3.2.1 P256-SHA256 VOPRF key derivation, proof verification, and output;
- RFC 5297 Appendix A.1 deterministic and Appendix A.2 nonce-based AES-SIV;
- NIST SP 800-38A Appendix F.5 AES-128-CTR;
- proof, evaluated-element, public-key, associated-data, ciphertext, capsule, and key tampering;
- exact `q` enforcement, allowlist-before-counting, principal separation, same-key rate-epoch renewal, revocation, and key rotation;
- retrieval, complete-byte deduplication, an injected digest collision, deletion reference counts, possession replay, and authorization separation;
- executable local, online, multiple-identity, and compromised-server dictionary cases.

Browser claim tests independently recalculate visible byte counts and decrypt displayed AES-CTR ciphertext with WebCrypto. Accessibility tests cover axe, keyboard navigation, both operating-system color preferences under the dark-only theme, reduced motion, and 320/380/390/768/1440-pixel reflow. Source mutations must make the relevant claim test fail while the clean committed baseline passes.

## Develop and verify

Requires Node.js 22.13 or newer within the 22.x line, Node.js 24.x, or Node.js 26 or newer. That range is the intersection supported by the locked development toolchain; the runtime Noble dependencies themselves require Node 20.19 or newer.

```sh
npm ci
npm run format:check
npm run typecheck
npm run lint
npm run test:coverage
npm run build
npm audit --audit-level=high
npx playwright install --with-deps chromium
npm run test:claims
npm run test:a11y
npm run test:mutations
```

`npm run ci` runs the static, unit, coverage, and build portion. GitHub Actions runs the complete gate before publishing GitHub Pages.

## Related labs

- [Envelope KMS](https://systemslibrarian.github.io/crypto-lab-envelope-kms/) compares randomized envelope encryption, wrapping, rewrapping, and compromise scope.
- [OPAQUE Gate](https://systemslibrarian.github.io/crypto-lab-opaque-gate/) gives an OPRF a different role inside a password-authentication protocol.
- [ORAM Vault](https://systemslibrarian.github.io/crypto-lab-oram-vault/) examines access-pattern leakage that ciphertext confidentiality alone does not hide.

The deployed lesson includes the runtime dependency copyright and MIT license text at [THIRD_PARTY_NOTICES.txt](https://systemslibrarian.github.io/crypto-lab-dedup-vault/THIRD_PARTY_NOTICES.txt).

## Primary sources

- Mihir Bellare, Sriram Keelveedhi, and Thomas Ristenpart, [Message-Locked Encryption and Secure Deduplication](https://eprint.iacr.org/2012/631), EUROCRYPT 2013.
- Mihir Bellare et al., [DupLESS: Server-Aided Encryption for Deduplicated Storage](https://www.usenix.org/conference/usenixsecurity13/technical-sessions/presentation/bellare), USENIX Security 2013.
- [RFC 9497: Oblivious Pseudorandom Functions](https://www.rfc-editor.org/rfc/rfc9497).
- [RFC 5297: Synthetic Initialization Vector (SIV) Authenticated Encryption](https://www.rfc-editor.org/rfc/rfc5297).
- [NIST SP 800-38A: Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/a/final).
- Shai Halevi et al., [Proofs of Ownership in Remote Storage Systems](https://eprint.iacr.org/2011/207).

## License

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
