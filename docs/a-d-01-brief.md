# A-D-01 implementation brief

## Roadmap target

Teach encrypted deduplication by directly comparing fresh encryption, local message-locked encryption, and server-aided derivation. Make equality leakage, dictionary pressure, storage accounting, ownership, deletion, revocation, rotation, and possession/authorization boundaries executable.

## Construction record

| Component       | Executable choice                                                                                                  | Important boundary                                                                                                                                                             |
| --------------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Local MLE       | `first128(SHA-256(P ∥ M))`, then AES-128-CTR with counter zero                                                     | Fixed lesson-specific `P` adapts DupLESS's randomly sampled public setup parameter; it gives domain separation, not dictionary resistance                                      |
| Server-aided    | RFC 9497 P256-SHA256 VOPRF over a length-framed, hashed application input; first 128 output bits form the data key | Modern adaptation of DupLESS, not its blind-RSA OPRF or its proven construction; proof assumes an authentically provisioned pinned public key                                  |
| Data encryption | AES-128-CTR                                                                                                        | A deterministic repeat of one exact value deliberately repeats key/counter and exposes equality; the pair must not encrypt a different value; there is no independent data tag |
| Key capsule     | RFC 5297 AES-SIV-CMAC-256 under a 32-byte combined key containing two AES-128 subkeys                              | Replaces DupLESS's HMAC-SHA256/AES-CTR SIV and omits its path/name handling; the per-user capsule binds owner, reference, scheme, and complete `Cdata`                         |
| Dedup index     | SHA-256 of `Cdata`, followed by complete-byte equality                                                             | Digest is a bucket hint, never equality authority                                                                                                                              |
| Possession      | Fresh nonce plus a short hash response over the complete modeled ciphertext                                        | Bounded whole-object-read challenge, not the paper's formal, leakage-resilient, scalable PoW                                                                                   |
| Rate budget     | In-memory exact `q` per allowlisted principal label and epoch; authentication is external to the model             | Delay mechanism, not Sybil/distribution/eventual-attempt defense                                                                                                               |

## Acceptance evidence

- Two equal uploads with fresh keys occupy two ciphertext objects.
- Two equal uploads in both deterministic modes occupy one ciphertext object and two distinct capsules.
- Physical data bytes, capsule bytes, total counted bytes, logical bytes, and ratio are separately visible.
- Local MLE is attacked offline with computed candidate ciphertexts; present and absent targets are distinct outcomes.
- Server-aided guesses execute under a modeled allowlist and exact query limits; principal separation, epoch renewal, and compromise are visible.
- The final VOPRF output is accepted only after proof verification; proof tampering fails.
- Storage verifies complete ciphertext before deduplication, including an injected-index-collision test.
- Possession success does not grant authorization; challenge replay fails.
- First-reference and final-reference deletion paths are both exercised.
- Revocation blocks future modeled reads and derivations but not cached material.
- VOPRF rotation changes the public key, derived key, and future ciphertext while old material remains internally consistent.
- Learner-visible adaptations and nonclaims stay present in the UI and README.
- Related-lab links connect the lesson to Envelope KMS, OPAQUE Gate, and ORAM Vault without conflating their threat models.

## Independent anchors

- RFC 9497 Appendix A.3.2.1 for P256-SHA256 VOPRF.
- RFC 5297 Appendix A.1 and A.2 for deterministic and nonce-based AES-SIV authenticated encryption.
- NIST SP 800-38A Appendix F.5 for AES-128-CTR.
- Bellare–Keelveedhi–Ristenpart MLE and DupLESS papers for deterministic/server-aided threat framing.
- Halevi–Harnik–Pinkas–Shulman-Peleg for the distinction between a short identifier and a proof-of-ownership protocol.

## Retained limitations

This is an all-in-one browser model using synthetic data. It does not provide production identity, distributed quota state, secret isolation, secure deletion, a formal proof of the VOPRF substitution, a formal PoW, authenticated content independent of the capsule, or constant-time execution. The exact Noble AES-SIV implementation postdates the package's cited independent audit.
