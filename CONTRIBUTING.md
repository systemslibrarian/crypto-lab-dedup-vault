# Contributing

Changes should preserve the distinction between an executable observation, a bounded model assumption, and a security claim.

Before submitting a change:

1. Read `README.md`, `SECURITY.md`, and `docs/a-d-01-brief.md`.
2. Cite primary cryptographic sources for construction or attack changes.
3. Add negative tests for failure behavior, not only a successful path.
4. Keep learner-visible values derived from the implementation rather than hardcoded.
5. Preserve keyboard access, dark-theme contrast, reduced-motion behavior, and phone reflow.
6. Do not weaken coverage, mutation, accessibility, or deployment gates to make CI green.
7. Run every command in the README verification block.

Never commit real files, credentials, tokens, personal data, or production endpoints. All lesson examples must remain synthetic.
