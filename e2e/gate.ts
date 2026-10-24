import AxeBuilder from "@axe-core/playwright";
import { expect, type Page } from "@playwright/test";

import { auditContrast, formatContrastFailures } from "./contrast";
import { auditNonText } from "./nontext";
import { NONTEXT_BASELINE } from "./nontext-baseline";

export const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];
export const NARROW = { width: 380, height: 900 };

/** Wait until finite animations and transitions have stayed quiet for six frames. */
export async function settle(page: Page, budgetMs = 4_000): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const state = window as unknown as {
        __quietFrames?: number;
        __settleStart?: number;
      };
      if (state.__settleStart === undefined) {
        state.__settleStart = performance.now();
      }
      const finish = (): boolean => {
        state.__quietFrames = 0;
        state.__settleStart = undefined;
        return true;
      };
      const running = document.getAnimations().filter((animation) => {
        if (animation.playState !== "running") return false;
        return animation.effect?.getComputedTiming?.().iterations !== Infinity;
      });
      state.__quietFrames =
        running.length === 0 ? (state.__quietFrames ?? 0) + 1 : 0;
      if (state.__quietFrames >= 6) return finish();
      if (performance.now() - (state.__settleStart ?? 0) > budget) {
        return finish();
      }
      return false;
    },
    budgetMs,
    { polling: "raf", timeout: 20_000 },
  );
}

/** Collect uncaught browser failures from page creation through the final scan. */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
  page.on("console", (message) => {
    if (message.type() === "error") {
      errors.push(`console.error: ${message.text()}`);
    }
  });
  return errors;
}

/** Assert the shared top bar is the document's only banner landmark. */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(["MAIN", "ARTICLE", "ASIDE", "NAV", "SECTION"]);
    const isBanner = (element: Element): boolean => {
      if (element.getAttribute("role") === "banner") return true;
      if (element.tagName !== "HEADER") return false;
      if (element.getAttribute("role")) return false;
      for (
        let parent = element.parentElement;
        parent;
        parent = parent.parentElement
      ) {
        if (scoped.has(parent.tagName)) return false;
      }
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(
      isBanner,
    ).length;
  });
  expect(banners, "exactly one banner landmark").toBe(1);
}

/**
 * Styled lists must retain explicit list/listitem semantics. Dedup Vault's
 * boundary evidence removes native bullets, so the generated list uses these
 * roles for Safari and VoiceOver rather than relying on visual styling.
 */
export async function assertListSemantics(page: Page): Promise<void> {
  const broken = await page.$$eval("ul[role], ol[role]", (lists) =>
    lists
      .filter(
        (list) =>
          list.getAttribute("role") !== "list" || list.children.length === 0,
      )
      .map(
        (list) =>
          `${list.tagName.toLowerCase()}[role=${list.getAttribute("role")}] with ${list.children.length} children`,
      ),
  );
  expect(
    broken,
    'explicit list roles must be non-empty role="list" containers',
  ).toEqual([]);
  await expect(page.locator(".boundary-list")).toHaveAttribute("role", "list");
  await expect(
    page.locator('.boundary-list > li:not([role="listitem"])'),
  ).toHaveCount(0);
}

/** The HTML `hidden` contract must win over any component display rule. */
export async function assertHiddenElementsDoNotPaint(
  page: Page,
  label: string,
): Promise<void> {
  const escaped = await page.$$eval("[hidden]", (elements) =>
    elements
      .filter((element) => {
        const style = getComputedStyle(element);
        const rect = element.getBoundingClientRect();
        return (
          style.display !== "none" &&
          style.visibility !== "hidden" &&
          rect.width > 0 &&
          rect.height > 0
        );
      })
      .map(
        (element) =>
          `${element.tagName.toLowerCase()}${element.id ? `#${element.id}` : ""}.${(element.getAttribute("class") ?? "").trim()}`,
      ),
  );
  expect(
    escaped,
    `[hidden] elements must not paint in state: ${label}`,
  ).toEqual([]);
}

/**
 * Load the production build under the requested operating-system preference.
 * The lesson itself is deliberately dark-only, and its anti-flash script must
 * replace even a previously stored light preference before the first scan.
 * Only structure is asserted here; learner-visible wording belongs to the
 * claims suite.
 */
export async function boot(
  page: Page,
  osScheme: "dark" | "light",
): Promise<void> {
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ colorScheme: osScheme, reducedMotion: "reduce" });
  await page.addInitScript(() => localStorage.setItem("theme", "light"));
  await page.goto(".");

  expect(
    await page.evaluate(
      () => matchMedia("(prefers-reduced-motion: reduce)").matches,
    ),
    "reduced-motion emulation must be active",
  ).toBe(true);
  expect(
    await page.evaluate(
      (scheme) => matchMedia(`(prefers-color-scheme: ${scheme})`).matches,
      osScheme,
    ),
    `${osScheme} OS color preference must be active`,
  ).toBe(true);
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  expect(await page.evaluate(() => localStorage.getItem("theme"))).toBe("dark");

  await assertSingleBanner(page);
  await expect(page.locator("main")).toHaveCount(1);
  await expect(page.locator("h1")).toHaveCount(1);
  await expect(page.locator("section.exhibit")).toHaveCount(5);
  await expect(page.locator("#comparison-form")).toHaveCount(1);
  await expect(page.locator("#file-input")).toHaveCount(1);
  await expect(
    page.locator('#comparison-form button[type="submit"]'),
  ).toHaveCount(1);
  await expect(page.locator('#run-status[role="status"]')).toHaveCount(1);

  const outputs = page.locator(".output[data-stale]");
  await expect(outputs).toHaveCount(4);
  await expect(page.locator('.output[data-stale="false"]')).toHaveCount(4);
  await expect(page.locator("#mode-comparison tbody tr")).toHaveCount(3);
  await expect(page.locator("#attack-output .result-card")).toHaveCount(9);
  await expect(page.locator("#roles-output article")).toHaveCount(6);
  await expect(page.locator(".boundary-list > li")).toHaveCount(9);
  await assertListSemantics(page);

  await expect(page.locator("details")).toHaveCount(1);
  await expect(page.locator("details[open]")).toHaveCount(0);
  await expect(page.locator("a.cl-skip-link")).toHaveAttribute("href", "#app");
  await expect(page.locator("#app")).toHaveCount(1);
  await expect(
    page.locator(
      "#theme-toggle, #themeToggle, .theme-toggle, .theme-toggle-btn, [data-theme-toggle], #cl-theme-toggle",
    ),
  ).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `boot under ${osScheme} OS preference`);
}

/** A reduced-motion rule may cancel animation without restoring visible text. */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const output: string[] = [];
    for (const element of Array.from(document.querySelectorAll("body *"))) {
      const ownText = Array.from(element.childNodes)
        .filter((node) => node.nodeType === Node.TEXT_NODE)
        .map((node) => node.textContent ?? "")
        .join("")
        .trim();
      if (!ownText) continue;
      if (
        !(element as HTMLElement).checkVisibility?.({
          checkVisibilityCSS: true,
        })
      ) {
        continue;
      }
      if (element.closest('[aria-hidden="true"]')) continue;
      let opacity = 1;
      for (
        let node: Element | null = element;
        node;
        node = node.parentElement
      ) {
        opacity *= Number.parseFloat(getComputedStyle(node).opacity);
      }
      if (opacity === 0) {
        output.push(
          `${element.tagName.toLowerCase()}.${(element.getAttribute("class") ?? "").trim()}`,
        );
      }
    }
    return [...new Set(output)];
  });
  expect(
    invisible,
    `visible text must not render at opacity zero in state: ${label}`,
  ).toEqual([]);
}

/** Assert WCAG 1.4.10 reflow without confusing an intentional inner scroller. */
export async function expectNoHorizontalOverflow(
  page: Page,
  label: string,
): Promise<void> {
  const overflow = await page.evaluate(() => {
    const root = document.documentElement;
    if (root.scrollWidth <= root.clientWidth + 1) return null;

    const clipped = (element: Element): boolean => {
      for (
        let parent = element.parentElement;
        parent && parent !== root;
        parent = parent.parentElement
      ) {
        const overflowX = getComputedStyle(parent).overflowX;
        if (["auto", "scroll", "hidden", "clip"].includes(overflowX)) {
          return true;
        }
      }
      return false;
    };

    const candidates = Array.from(document.querySelectorAll("body *"))
      .map((element) => ({ element, rect: element.getBoundingClientRect() }))
      .filter(({ rect }) => rect.width > 0 && rect.right > root.clientWidth + 1)
      .sort((left, right) => right.rect.right - left.rect.right);
    const widest =
      candidates.find(({ element }) => !clipped(element)) ?? candidates[0];
    return {
      clientWidth: root.clientWidth,
      scrollWidth: root.scrollWidth,
      widest: widest
        ? `${clipped(widest.element) ? "[clipped] " : ""}${widest.element.tagName.toLowerCase()}${widest.element.id ? `#${widest.element.id}` : ""} @${Math.round(widest.rect.width)}px right=${Math.round(widest.rect.right)}`
        : "(none identified)",
    };
  });
  expect(
    overflow,
    `page must not scroll horizontally in state: ${label}`,
  ).toBeNull();
}

/** Every scrollable region needs a keyboard route. */
export async function expectScrollersReachable(
  page: Page,
  label: string,
): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const focusable =
      'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>("body *"))
      .filter(
        (element) =>
          element.scrollWidth > element.clientWidth + 1 ||
          element.scrollHeight > element.clientHeight + 1,
      )
      .filter((element) => {
        const style = getComputedStyle(element);
        return (
          ["auto", "scroll"].includes(style.overflowX) ||
          ["auto", "scroll"].includes(style.overflowY)
        );
      })
      .filter(
        (element) => element.tabIndex < 0 && !element.querySelector(focusable),
      )
      .map(
        (element) =>
          `${element.tagName.toLowerCase()}.${(element.getAttribute("class") ?? "").trim()} (${element.scrollWidth}x${element.scrollHeight} in ${element.clientWidth}x${element.clientHeight})`,
      );
  });
  expect(
    [...new Set(unreachable)],
    `scrolling regions without a keyboard route in state: ${label}`,
  ).toEqual([]);
}

/** A focus target may not remain in the tab order while painting nothing. */
export async function expectNoInvisibleFocusTargets(
  page: Page,
  label: string,
): Promise<void> {
  const invisible = await page.evaluate(() => {
    const selector =
      'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    const output: string[] = [];
    for (const element of Array.from(
      document.querySelectorAll<HTMLElement>(selector),
    )) {
      if (element.tabIndex < 0) continue;
      if (!element.checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let opacity = 1;
      for (
        let node: Element | null = element;
        node;
        node = node.parentElement
      ) {
        opacity *= Number.parseFloat(getComputedStyle(node).opacity);
      }
      const rect = element.getBoundingClientRect();
      if (opacity !== 0 && rect.width > 0 && rect.height > 0) continue;
      const previous = document.activeElement as HTMLElement | null;
      element.focus();
      const acceptedFocus = document.activeElement === element;
      previous?.focus?.();
      if (acceptedFocus) {
        output.push(
          `${element.tagName.toLowerCase()}${element.id ? `#${element.id}` : ""} (opacity ${opacity}, ${Math.round(rect.width)}x${Math.round(rect.height)})`,
        );
      }
    }
    return [...new Set(output)];
  });
  expect(
    invisible,
    `focusable elements that paint nothing in state: ${label}`,
  ).toEqual([]);
}

const COLLECTING = Boolean(process.env.A11Y_COLLECT);
const collected: string[] = [];

function record(message: string): void {
  collected.push(message);
  console.info(`\n[A11Y_COLLECT #${collected.length}] ${message}`);
}

function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n${JSON.stringify(actual, null, 2)}`);
  }
}

async function soft(check: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return check();
  try {
    await check();
  } catch (error) {
    record(String(error).slice(0, 6_000));
  }
}

export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(
    collected,
    `A11Y_COLLECT recorded ${collected.length} failure(s)`,
  ).toEqual([]);
}

const nonTextSeen = new Set<string>();

async function expectNoNewNonTextFailures(
  page: Page,
  label: string,
): Promise<void> {
  const findings = await auditNonText(page);
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const finding of findings) {
      console.info(
        `NTCAP|${finding.kind}|${finding.selector}|${finding.ratio}|${finding.required}|${/POSITIONED/.test(finding.detail)}`,
      );
    }
    return;
  }

  const problems: string[] = [];
  for (const finding of findings) {
    const key = `${finding.kind}|${finding.selector}`;
    nonTextSeen.add(key);
    const baseline = NONTEXT_BASELINE[key];
    if (!baseline) {
      problems.push(
        `NEW ${finding.ratio}:1 (needs ${finding.required}:1) [${finding.kind}] ${finding.selector} — ${finding.detail}`,
      );
    } else if (finding.ratio < baseline.ratio - 0.01) {
      problems.push(
        `WORSE ${finding.selector}: ${finding.ratio}:1; baseline ${baseline.ratio}:1`,
      );
    }
  }
  expect(
    problems,
    `new or worsened non-text contrast in state: ${label}`,
  ).toEqual([]);
}

export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter(
    (key) => !nonTextSeen.has(key),
  );
  expect(
    unseen,
    "baselined non-text findings no longer reached; remove fixed entries or restore coverage",
  ).toEqual([]);
}

/**
 * Scan one real learner-reachable state with independent axe, arithmetic text,
 * non-text/generated-content, keyboard, focus, and reflow oracles.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  await assertHiddenElementsDoNotPaint(page, label);

  // withTags() and withRules() both set axe's runOnly option, so these must be
  // separate runs or the landmark rules silently replace the WCAG rules.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      "landmark-no-duplicate-banner",
      "landmark-unique",
      "landmark-one-main",
      "landmark-complementary-is-top-level",
    ])
    .analyze();
  const violations = [...wcag.violations, ...landmarks.violations].map(
    (violation) => ({
      state: label,
      id: violation.id,
      impact: violation.impact,
      help: violation.help,
      nodes: violation.nodes.map((node) => node.target.join(" ")).slice(0, 8),
    }),
  );
  softExpect(violations, `axe violations in state: ${label}`, []);

  const incomplete = [...wcag.incomplete, ...landmarks.incomplete]
    .filter((result) => result.id !== "color-contrast")
    .map((result) => ({
      state: label,
      id: result.id,
      nodes: result.nodes.map((node) => node.target.join(" ")).slice(0, 8),
    }));
  softExpect(
    incomplete,
    `unexplained axe incomplete results in state: ${label}`,
    [],
  );

  const contrast = [
    ...new Set(formatContrastFailures(await auditContrast(page))),
  ];
  softExpect(
    contrast,
    `measured text contrast failures in state: ${label}`,
    [],
  );

  const hiddenContrast = [
    ...new Set(
      formatContrastFailures(
        await auditContrast(
          page,
          '[aria-hidden="true"], [aria-hidden="true"] *',
          true,
        ),
      ),
    ),
  ];
  softExpect(
    hiddenContrast,
    `measured aria-hidden contrast failures in state: ${label}`,
    [],
  );

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoInvisibleFocusTargets(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

/** Drive every distinct visual state this single-control lesson exposes. */
export async function driveAllStates(
  page: Page,
  context: string,
): Promise<void> {
  const input = page.locator("#file-input");
  const runButton = page.getByRole("button", { name: "Run all experiments" });
  const scanAt = (state: string): Promise<void> =>
    scan(page, `${context} / ${state}`);

  await scanAt("arrival with computed evidence and the source disclosure shut");

  await page.evaluate(() =>
    (document.activeElement as HTMLElement | null)?.blur(),
  );
  await page.keyboard.press("Tab");
  await expect(page.locator(".cl-skip-link")).toBeFocused();
  await scanAt("skip link focused and visible");

  await input.focus();
  await expect(input).toBeFocused();
  await scanAt("synthetic-file input focused");

  await input.fill("Changed nonempty accessibility fixture");
  await expect(page.locator('.output[data-stale="true"]')).toHaveCount(4);
  await scanAt("changed input with generated stale-evidence labels");

  await input.fill("");
  await runButton.click();
  await expect(page.locator('.output[data-stale="true"]')).toHaveCount(4);
  await expect(page.locator("#run-status")).not.toBeEmpty();
  await scanAt("empty submission rejected while prior evidence remains stale");

  await input.fill("A".repeat(512));
  await runButton.click();
  await expect(page.locator('.output[data-stale="false"]')).toHaveCount(4);
  await expect(page.locator("#mode-comparison tbody tr")).toHaveCount(3);
  await expect(page.locator("#run-status")).not.toBeEmpty();
  await scanAt("maximum-length input recomputed into fresh evidence");

  await page.locator("details > summary").click();
  await expect(page.locator("details[open]")).toHaveCount(1);
  await scanAt("primary-source disclosure opened through its summary");

  await runButton.hover();
  await scanAt("experiment button hovered");

  await page.locator(".cl-topbar .cl-btn").first().hover();
  await scanAt("top-bar control hovered");

  await page.locator("details > summary").focus();
  await expect(page.locator("details > summary")).toBeFocused();
  await scanAt("open disclosure summary focused");
}
