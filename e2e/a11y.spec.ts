import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const pageErrors = new WeakMap<Page, string[]>();

test.beforeEach(async ({ page }) => {
  const errors: string[] = [];
  pageErrors.set(page, errors);
  page.on("pageerror", (error) => errors.push(error.message));
});

test.afterEach(async ({ page }) => {
  expect(pageErrors.get(page) ?? []).toEqual([]);
});

async function loadAndScan(page: Page): Promise<void> {
  await page.goto(".");
  await expect(page.locator("#comparison-output")).toHaveAttribute(
    "data-stale",
    "false",
  );
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(
    results.violations,
    JSON.stringify(results.violations, null, 2),
  ).toEqual([]);
}

for (const colorScheme of ["dark", "light"] as const) {
  test(`dark-only lesson is accessible when OS preference is ${colorScheme}`, async ({
    page,
  }) => {
    await page.emulateMedia({ colorScheme });
    await loadAndScan(page);
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await page
      .locator("#file-input")
      .fill("Changed input for the accessibility state");
    await expect(page.locator("#comparison-output")).toHaveAttribute(
      "data-stale",
      "true",
    );
    let results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
      .analyze();
    expect(
      results.violations,
      JSON.stringify(results.violations, null, 2),
    ).toEqual([]);
    await page.getByRole("button", { name: "Run all experiments" }).click();
    results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
      .analyze();
    expect(
      results.violations,
      JSON.stringify(results.violations, null, 2),
    ).toEqual([]);
  });
}

for (const width of [320, 380, 390, 768, 1440]) {
  test(`reflows without page-level horizontal clipping at ${width}px`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 900 });
    await loadAndScan(page);
    const overflow = await page.evaluate(() => ({
      document:
        document.documentElement.scrollWidth -
        document.documentElement.clientWidth,
      body: document.body.scrollWidth - document.body.clientWidth,
    }));
    expect(overflow.document).toBeLessThanOrEqual(1);
    expect(overflow.body).toBeLessThanOrEqual(1);
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
  await expect(page.locator(".skip-link")).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();
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
  await expect(page.locator(".skip-link")).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.locator(".brand")).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Catalog" })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Source" })).toBeFocused();
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
        return duration.trim().endsWith("ms") ? value / 1000 : value;
      }),
  }));
  expect(styles.scrollBehavior).toBe("auto");
  expect(styles.buttonTransitionSeconds.length).toBeGreaterThan(0);
  expect(
    styles.buttonTransitionSeconds.every((seconds) => seconds <= 0.00001),
  ).toBe(true);
});
