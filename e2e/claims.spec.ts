import { webcrypto } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";

const DEFAULT_FILE = "Campus payroll closes Friday at 17:00.";
const pageErrors = new WeakMap<Page, string[]>();

test.beforeEach(async ({ page }) => {
  const errors: string[] = [];
  pageErrors.set(page, errors);
  page.on("pageerror", (error) => errors.push(error.message));
});

test.afterEach(async ({ page }) => {
  expect(pageErrors.get(page) ?? []).toEqual([]);
});

type ModeRow = {
  mode: string;
  keysEqual: boolean;
  ciphertextEqual: boolean;
  firstKey: string;
  secondKey: string;
  firstCiphertext: string;
  secondCiphertext: string;
  firstCapsule: string;
  secondCapsule: string;
  blobs: number;
  logicalData: number;
  uniqueData: number;
  capsuleBytes: number;
  capsulesDistinct: boolean;
  total: number;
  ratio: number;
  blobsText: string;
  logicalDataText: string;
  uniqueDataText: string;
  capsuleSummary: string;
  totalText: string;
  ratioText: string;
};

async function load(page: Page): Promise<void> {
  await page.goto(".");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(
    "Dedup Vault",
  );
  await expect(page.locator("#comparison-output")).toHaveAttribute(
    "data-stale",
    "false",
  );
}

async function rows(page: Page): Promise<ModeRow[]> {
  return page.locator("#mode-comparison tbody tr").evaluateAll((items) =>
    items.map((row) => {
      const cells = row.querySelectorAll("td");
      const keys = cells[0].querySelectorAll("code");
      return {
        mode: row.getAttribute("data-mode") ?? "",
        keysEqual: cells[0].getAttribute("data-equal") === "true",
        ciphertextEqual: cells[1].getAttribute("data-equal") === "true",
        firstKey: keys[0]?.getAttribute("data-hex") ?? "",
        secondKey: keys[1]?.getAttribute("data-hex") ?? "",
        firstCiphertext:
          cells[1].querySelectorAll("code")[0]?.getAttribute("data-hex") ?? "",
        secondCiphertext:
          cells[1].querySelectorAll("code")[1]?.getAttribute("data-hex") ?? "",
        firstCapsule:
          cells[5].querySelectorAll("code")[0]?.getAttribute("data-hex") ?? "",
        secondCapsule:
          cells[5].querySelectorAll("code")[1]?.getAttribute("data-hex") ?? "",
        blobs: Number(cells[2].getAttribute("data-value")),
        logicalData: Number(cells[3].getAttribute("data-value")),
        uniqueData: Number(cells[4].getAttribute("data-value")),
        capsuleBytes: Number(cells[5].getAttribute("data-bytes")),
        capsulesDistinct: cells[5].getAttribute("data-distinct") === "true",
        total: Number(cells[6].getAttribute("data-value")),
        ratio: Number(cells[7].getAttribute("data-value")),
        blobsText: cells[2].textContent?.trim() ?? "",
        logicalDataText: cells[3].textContent?.trim() ?? "",
        uniqueDataText: cells[4].textContent?.trim() ?? "",
        capsuleSummary:
          cells[5].querySelector("span")?.textContent?.trim() ?? "",
        totalText: cells[6].textContent?.trim() ?? "",
        ratioText: cells[7].textContent?.trim() ?? "",
      };
    }),
  );
}

function fromHex(value: string): Uint8Array<ArrayBuffer> {
  if (value.length % 2 !== 0) throw new Error("invalid hex");
  const output = new Uint8Array(new ArrayBuffer(value.length / 2));
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}

test.describe("Dedup Vault learner-visible claims", () => {
  test("three-mode table derives exact equality and byte accounting", async ({
    page,
  }) => {
    await load(page);
    const measured = await rows(page);
    expect(measured.map((row) => row.mode)).toEqual([
      "fresh",
      "local-mle",
      "server-aided",
    ]);
    const fileBytes = new TextEncoder().encode(DEFAULT_FILE).length;

    for (const row of measured) {
      expect(row.keysEqual).toBe(row.firstKey === row.secondKey);
      expect(row.ciphertextEqual).toBe(
        row.firstCiphertext === row.secondCiphertext,
      );
      expect(row.capsulesDistinct).toBe(row.firstCapsule !== row.secondCapsule);
      const firstCiphertextBytes = fromHex(row.firstCiphertext).length;
      const secondCiphertextBytes = fromHex(row.secondCiphertext).length;
      const expectedUniqueData = row.ciphertextEqual
        ? firstCiphertextBytes
        : firstCiphertextBytes + secondCiphertextBytes;
      const firstCapsuleBytes = fromHex(row.firstCapsule).length;
      const secondCapsuleBytes = fromHex(row.secondCapsule).length;
      const expectedCapsuleBytes = firstCapsuleBytes + secondCapsuleBytes;
      const expectedBlobs = row.ciphertextEqual ? 1 : 2;
      const expectedTotal = expectedUniqueData + expectedCapsuleBytes;
      const expectedRatio = (fileBytes * 2) / expectedUniqueData;

      expect(firstCiphertextBytes).toBe(fileBytes);
      expect(secondCiphertextBytes).toBe(fileBytes);
      expect(row.blobs).toBe(expectedBlobs);
      expect(row.blobsText).toBe(String(expectedBlobs));
      expect(row.logicalData).toBe(fileBytes * 2);
      expect(row.logicalDataText).toBe(`${fileBytes * 2} B`);
      expect(row.uniqueData).toBe(expectedUniqueData);
      expect(row.uniqueDataText).toBe(`${expectedUniqueData} B`);
      expect(firstCapsuleBytes).toBe(secondCapsuleBytes);
      expect(row.capsuleBytes).toBe(expectedCapsuleBytes);
      expect(row.capsuleSummary).toBe(
        `2 × ${firstCapsuleBytes} B; distinct: ${row.capsulesDistinct ? "yes" : "no"}.`,
      );
      expect(row.total).toBe(expectedTotal);
      expect(row.totalText).toBe(`${expectedTotal} B`);
      expect(row.ratio).toBe(expectedRatio);
      expect(row.ratioText).toBe(`${expectedRatio.toFixed(2)}×`);
    }

    expect(measured[0]).toMatchObject({
      keysEqual: false,
      ciphertextEqual: false,
      blobs: 2,
      logicalData: fileBytes * 2,
      uniqueData: fileBytes * 2,
      capsuleBytes: 64,
      capsulesDistinct: true,
      total: fileBytes * 2 + 64,
      ratio: 1,
    });
    for (const row of measured.slice(1)) {
      expect(row).toMatchObject({
        keysEqual: true,
        ciphertextEqual: true,
        blobs: 1,
        logicalData: fileBytes * 2,
        uniqueData: fileBytes,
        capsuleBytes: 64,
        capsulesDistinct: true,
        total: fileBytes + 64,
        ratio: 2,
      });
    }
    expect(measured[1].firstCiphertext).not.toBe(measured[2].firstCiphertext);
  });

  test("displayed AES-CTR key independently decrypts displayed ciphertext", async ({
    page,
  }) => {
    await load(page);
    const measured = await rows(page);
    for (const row of measured) {
      const key = await webcrypto.subtle.importKey(
        "raw",
        fromHex(row.firstKey),
        { name: "AES-CTR" },
        false,
        ["decrypt"],
      );
      const opened = await webcrypto.subtle.decrypt(
        { name: "AES-CTR", counter: new Uint8Array(16), length: 128 },
        key,
        fromHex(row.firstCiphertext),
      );
      expect(new TextDecoder().decode(opened)).toBe(DEFAULT_FILE);
    }
  });

  test("(DV-21) role views keep key-server, budgeted-client, and combined-compromise capabilities distinct", async ({
    page,
  }) => {
    await load(page);
    const roles = await page
      .locator("#roles-output article")
      .evaluateAll((items) =>
        items.map((item) => ({
          title: item.querySelector("h3")?.textContent?.trim() ?? "",
          body: item.querySelector("p")?.textContent?.trim() ?? "",
        })),
      );
    expect(roles.map(({ title }) => title)).toEqual([
      "Client",
      "Key server",
      "Storage server",
      "Storage-only attacker",
      "Allowlisted guessing client",
      "Combined key-server and ciphertext compromise",
    ]);
    expect(roles[1].body).toContain(
      "neither plaintext nor stored target ciphertext",
    );
    expect(roles[1].body).toContain("lacks the equality target");
    expect(roles[4].body).toContain("per-principal, per-epoch request budget");
    expect(roles[5].body).toContain(
      "access to copied or stored target ciphertext",
    );
  });

  test("(DV-18) dictionary outcomes follow computed comparisons and exact query budgets", async ({
    page,
  }) => {
    await load(page);
    const cards = await page
      .locator("#attack-output .result-card")
      .evaluateAll((items) =>
        items.map((item) => ({
          title: item.querySelector("h3")?.textContent?.trim() ?? "",
          outcome: item.getAttribute("data-outcome"),
          text: item.textContent?.replace(/\s+/g, " ").trim() ?? "",
        })),
      );
    expect(cards).toHaveLength(9);
    expect(cards.map(({ title, outcome }) => ({ title, outcome }))).toEqual([
      { title: "Local MLE: target in dictionary", outcome: "recovered" },
      { title: "Local MLE: target absent", outcome: "no-match" },
      { title: "Server-aided: within q = 3", outcome: "recovered" },
      { title: "Server-aided: beyond q = 2", outcome: "rate-limited" },
      { title: "Unknown identity", outcome: "principal-rejected" },
      { title: "First allowlisted principal", outcome: "rate-limited" },
      { title: "Second allowlisted principal", outcome: "recovered" },
      { title: "Next rate epoch", outcome: "recovered" },
      { title: "Key server compromised", outcome: "recovered" },
    ]);
    expect(cards[0].text).toContain("completed comparisons: 3");
    expect(cards[1].text).toContain("completed comparisons: 2");
    expect(cards[2].text).toContain("completed comparisons: 3");
    expect(cards[3].text).toContain("completed comparisons: 2");
    expect(cards[4].text).toContain("completed comparisons: 0");
    expect(cards[5].text).toContain("completed comparisons: 2");
    expect(cards[6].text).toContain("completed comparisons: 1");
    expect(cards[7].text).toContain("completed comparisons: 1");
    expect(cards[8].text).toContain("completed comparisons: 3");
    await expect(page.locator(".length-control")).toHaveAttribute(
      "data-equal",
      "true",
    );
    await expect(page.locator(".length-control")).toContainText(
      `target and every candidate are ${new TextEncoder().encode(DEFAULT_FILE).length} bytes`,
    );
    await expect(page.locator(".proof-result")).toHaveAttribute(
      "data-rejected",
      "true",
    );
  });

  test("(DV-12, DV-22) all lifecycle verdicts stay green while cached-copy revocation remains a visible limit", async ({
    page,
  }) => {
    await load(page);
    await expect(page.locator(".boundary-list li")).toHaveCount(9);
    await expect(
      page.locator('.boundary-list li[data-passed="false"]'),
    ).toHaveCount(0);
    const text = await page.locator(".boundary-list").innerText();
    expect(text).toContain("Identifier alone is rejected");
    expect(text).toContain("Possession does not grant a reference");
    expect(text).toContain("First deletion retains shared blob");
    expect(text).toContain("Last deletion removes blob");
    expect(text).toContain("Revocation is prospective");
    expect(text).toContain("Rotation changes future derivation");
    expect(text).toContain("VOPRF proof tamper is rejected");
    const revocation = page
      .locator(".boundary-list li")
      .filter({ hasText: "Revocation is prospective" });
    await expect(revocation).toHaveAttribute("data-passed", "true");
    await expect(revocation).toContainText(
      "cached authorized copy still opens",
    );
  });

  test("(DV-10, DV-23, DV-24) freshness distinguishes changes, no-ops, and rejected empty input", async ({
    page,
  }) => {
    await load(page);
    const input = page.locator("#file-input");
    const outputIds = [
      "comparison-output",
      "attack-output",
      "roles-output",
      "boundary-output",
    ];

    await input.dispatchEvent("input");
    for (const id of outputIds) {
      await expect(page.locator(`#${id}`)).toHaveAttribute(
        "data-stale",
        "false",
      );
    }
    await expect(page.locator("#run-status")).toContainText(
      "no rerun is needed",
    );

    await input.fill("A temporary change");
    await input.fill(DEFAULT_FILE);
    for (const id of outputIds) {
      await expect(page.locator(`#${id}`)).toHaveAttribute(
        "data-stale",
        "false",
      );
    }
    await expect(page.locator("#run-status")).toContainText(
      "no rerun is needed",
    );

    await input.fill("A changed synthetic file — α");
    for (const id of outputIds) {
      await expect(page.locator(`#${id}`)).toHaveAttribute(
        "data-stale",
        "true",
      );
    }
    await expect(page.locator("#run-status")).toContainText("stale");

    await page.getByRole("button", { name: "Run all experiments" }).click();
    for (const id of outputIds) {
      await expect(page.locator(`#${id}`)).toHaveAttribute(
        "data-stale",
        "false",
      );
    }
    await expect(page.locator("#run-status")).toContainText(
      "Fresh evidence computed",
    );
    const changed = await rows(page);
    const changedBytes = new TextEncoder().encode(
      "A changed synthetic file — α",
    ).length;
    expect(changed[0].total).toBe(changedBytes * 2 + 64);
    expect(changed[1].total).toBe(changedBytes + 64);

    await input.dispatchEvent("input");
    for (const id of outputIds) {
      await expect(page.locator(`#${id}`)).toHaveAttribute(
        "data-stale",
        "false",
      );
    }

    await input.fill("");
    for (const id of outputIds) {
      await expect(page.locator(`#${id}`)).toHaveAttribute(
        "data-stale",
        "true",
      );
    }
    await page.getByRole("button", { name: "Run all experiments" }).click();
    await expect(page.locator("#run-status")).toHaveText(
      "Enter at least one character.",
    );
    for (const id of outputIds) {
      await expect(page.locator(`#${id}`)).toHaveAttribute(
        "data-stale",
        "true",
      );
    }
  });

  test("(DV-11) adaptation and limitations remain visible rather than implied", async ({
    page,
  }) => {
    await load(page);
    const exhibit = page.locator("#exhibit-5-heading").locator("..");
    await expect(exhibit).toContainText("modern adaptation");
    await expect(exhibit).toContainText("pinned public key");
    await expect(exhibit).toContainText(
      "authentic provisioning of that key is outside this model",
    );
    await expect(exhibit).toContainText(
      "proof does not transfer automatically",
    );
    await expect(exhibit).toContainText("Rate limits delay dictionary search");
    await expect(exhibit).toContainText(
      "not the paper’s formal, leakage-resilient, scalable proof-of-ownership construction",
    );
    await expect(exhibit).toContainText(
      "does not promise constant-time execution",
    );
    await expect(exhibit).toContainText("postdates that independent audit");
    await expect(
      exhibit.getByRole("link", { name: "Envelope KMS" }),
    ).toHaveAttribute(
      "href",
      "https://systemslibrarian.github.io/crypto-lab-envelope-kms/",
    );
    await expect(
      exhibit.getByRole("link", { name: "OPAQUE Gate" }),
    ).toHaveAttribute(
      "href",
      "https://systemslibrarian.github.io/crypto-lab-opaque-gate/",
    );
    await expect(
      exhibit.getByRole("link", { name: "ORAM Vault" }),
    ).toHaveAttribute(
      "href",
      "https://systemslibrarian.github.io/crypto-lab-oram-vault/",
    );
  });
});
