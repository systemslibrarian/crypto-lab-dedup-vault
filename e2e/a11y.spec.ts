import { expect, test, type Page } from "@playwright/test";

import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  expectNoHorizontalOverflow,
  NARROW,
  reportCollected,
  scan,
  watchPageErrors,
} from "./gate";

const pageErrors = new WeakMap<Page, string[]>();

test.beforeEach(async ({ page }) => {
  pageErrors.set(page, watchPageErrors(page));
});

test.afterEach(async ({ page }) => {
  const errors = pageErrors.get(page) ?? [];
  expect(errors, errors.join("\n")).toEqual([]);
});

const comprehensiveCases = [
  { osScheme: "dark", viewport: undefined, label: "dark OS preference" },
  {
    osScheme: "light",
    viewport: NARROW,
    label: "light OS preference at 380px",
  },
] as const;

for (const { osScheme, viewport, label } of comprehensiveCases) {
  test(`honest WCAG A/AA gate under ${label}`, async ({ page }) => {
    test.setTimeout(900_000);
    if (viewport) await page.setViewportSize(viewport);
    await boot(page, osScheme);
    await driveAllStates(page, label);
    expectBaselineNotStale();
    reportCollected();
  });
}

for (const width of [320, 380, 390, 768, 1440]) {
  test(`reflows without page-level horizontal clipping at ${width}px`, async ({
    page,
  }) => {
    test.setTimeout(300_000);
    await page.setViewportSize({ width, height: 900 });
    await boot(page, "dark");
    await scan(page, `arrival at ${width}px`);
    await expectNoHorizontalOverflow(page, `arrival at ${width}px`);
    await expect(
      page.getByRole("button", { name: "Run all experiments" }),
    ).toBeVisible();
    await expect(page.locator("#exhibit-5-heading")).toBeVisible();
  });
}

test("skip link, form, and disclosure are keyboard reachable", async ({
  page,
}) => {
  await page.goto(".");
  await page.keyboard.press("Tab");
  await expect(page.locator(".cl-skip-link")).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#app")).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.locator("#file-input")).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("button", { name: "Run all experiments" }),
  ).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Noble Curves’ security record" }),
  ).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Noble Ciphers’ security record" }),
  ).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "AES-SIV entered in 2.1.1" }),
  ).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.locator("summary")).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("details")).toHaveAttribute("open", "");
});

test("project links are keyboard reachable from a fresh document", async ({
  page,
}) => {
  await page.goto(".");
  await page.keyboard.press("Tab");
  await expect(page.locator(".cl-skip-link")).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Crypto Lab home" }),
  ).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Crypto Lab menu" }),
  ).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "View this project on GitHub" }),
  ).toBeFocused();
});

test("fleet chrome, bounded hero, and teaching footer remain present", async ({
  page,
}) => {
  await page.goto(".");
  await expect(page).toHaveTitle("Dedup Vault — crypto-lab");
  await expect(page.getByRole("banner")).toHaveCount(1);
  await expect(page.locator("h1.cl-hero-title")).toHaveText("Dedup Vault");
  await expect(page.locator(".cl-hero-sub")).toContainText(
    "Message-locked encryption",
  );
  await expect(page.locator(".cl-hero-why-label")).toHaveText("WHY IT MATTERS");
  await expect(page.locator(".scope-banner")).toContainText(
    "not a production storage design",
  );
  await expect(page.locator(".scripture-footer")).toContainText(
    "do it all for the glory of God",
  );
  await expect(page.locator('link[rel="icon"]')).toHaveAttribute(
    "href",
    /^data:image\/svg\+xml/,
  );
  expect(
    await page.evaluate(() => ({
      attribute: document.documentElement.dataset.theme,
      stored: localStorage.getItem("theme"),
    })),
  ).toEqual({ attribute: "dark", stored: "dark" });
});

test("reduced-motion preference disables smooth scrolling and animation", async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto(".");
  const styles = await page.evaluate(() => ({
    scrollBehavior: getComputedStyle(document.documentElement).scrollBehavior,
    buttonTransitionSeconds: getComputedStyle(document.querySelector("button")!)
      .transitionDuration.split(",")
      .map((duration) => {
        const value = Number.parseFloat(duration);
        return duration.trim().endsWith("ms") ? value / 1_000 : value;
      }),
  }));
  expect(styles.scrollBehavior).toBe("auto");
  expect(styles.buttonTransitionSeconds.length).toBeGreaterThan(0);
  expect(
    styles.buttonTransitionSeconds.every((seconds) => seconds <= 0.00001),
  ).toBe(true);
});
