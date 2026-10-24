/**
 * Known WCAG 1.4.11 or generated-content findings.
 *
 * This starts empty deliberately. New findings fail the gate; if a future
 * finding is temporarily baselined, the gate also fails when it worsens or
 * disappears so this list cannot become a permanent exemption.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {};
