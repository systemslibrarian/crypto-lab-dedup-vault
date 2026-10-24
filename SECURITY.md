# Security policy and model

## Purpose

Dedup Vault is an educational, client-side simulation. Do not use it to protect real files, keys, accounts, or storage services.

## Modeled roles

- A client holds plaintext and a per-user capsule-wrapping key.
- A VOPRF key server holds one server secret, accepts an allowlisted principal label that stands in for an external authentication decision, and applies a per-principal count within an in-memory epoch. It does not implement authentication.
- A storage server holds deterministic data ciphertext, owner/reference metadata, and per-user capsules.
- Attack routines receive only the capabilities named by their scenario.

Those roles are logical. They execute in the same JavaScript realm and provide no actual isolation.

## Properties exercised

- Equal local-MLE or server-aided plaintexts deterministically create equal data ciphertext under one key-server generation.
- Fresh independent keys normally prevent equal ciphertext and therefore prevent deduplication.
- AES-SIV detects changes to capsule ciphertext or its bound owner, reference, complete data ciphertext, and scheme label.
- Capsule owner and reference identifiers reject malformed UTF-16 before UTF-8 encoding, preventing distinct unpaired-surrogate strings from collapsing to the same replacement bytes.
- RFC 9497 VOPRF finalization rejects a changed proof, evaluated element, or coherent response under a key different from the client-pinned public key. The proof does not authenticate that pinned key; provisioning its trust is outside the model.
- The key server rejects labels outside its modeled allowlist and revoked principals before counting, then permits exactly `q` requests per principal and epoch.
- A digest collision cannot cause unequal content ciphertexts to merge because the complete bytes are compared.
- Removing one reference leaves a shared blob; removing the final reference deletes it.
- A possession response neither creates a storage reference nor bypasses authorization.

## Deliberate nonclaims

The lab does not claim semantic security for predictable files, plaintext integrity independent of the capsule, production authentication, Sybil resistance, distributed rate limiting, erasure of cached copies, post-compromise security, formal proof of the VOPRF adaptation, proof of plaintext ownership, side-channel resistance, or compliance/FIPS validation.

AES-SIV authenticates the bytes and associated data presented to it. Without trusted external version state, this model does not detect rollback or replay of an older valid data-ciphertext/capsule pair.

The deterministic modes deliberately repeat a key and fixed AES-CTR counter only for repeat encryption of the exact same plaintext value, exposing equality and departing from ordinary CTR counter-uniqueness. The key is intended for one distinct plaintext value; using it with a different value exposes the plaintext XOR. That teaching invariant is not an operational key-management control.

## Dependency qualification

The runtime dependencies are exactly pinned. The VOPRF and AES-SIV implementations are tested against primary-source vectors. [Noble Curves' security record](https://github.com/paulmillr/noble-curves/blob/main/README.md#security) records an all-scope Trail of Bits review at version 2.3.0; the pinned 2.4.0 release is later. [Noble Ciphers' security record](https://github.com/paulmillr/noble-ciphers/blob/main/README.md#security) records an all-scope Cure53 review at version 1.0.0, and its [2.1.1 release record](https://github.com/paulmillr/noble-ciphers/releases/tag/2.1.1) shows that AES-SIV was introduced later. Current Noble releases and this exact AES-SIV code are therefore not represented as independently audited production components. See `THIRD_PARTY_NOTICES.md` for licensing.

## Reporting

Report a suspected vulnerability privately through the repository owner's established GitHub security contact. Do not include real user data, secrets, or credentials in an issue or demonstration.
