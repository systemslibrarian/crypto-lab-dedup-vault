import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "html", "lcov"],
      include: ["src/**/*.ts"],
      exclude: [
        "src/main.ts",
        "src/ui/**",
        "src/**/*.test.ts",
        "src/**/*.d.ts",
      ],
      thresholds: {
        "src/crypto/**": {
          statements: 95,
          branches: 88,
          functions: 95,
          lines: 95,
        },
        "src/model/**": {
          statements: 90,
          branches: 85,
          functions: 90,
          lines: 90,
        },
        "src/attacks/**": {
          statements: 95,
          branches: 90,
          functions: 95,
          lines: 95,
        },
      },
    },
  },
});
