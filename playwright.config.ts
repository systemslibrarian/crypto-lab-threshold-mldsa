import { defineConfig, devices } from '@playwright/test';

const PORT = 4314;
const BASE = '/crypto-lab-threshold-mldsa/';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: 'list',
  use: {
    baseURL: `http://localhost:${PORT}${BASE}`,
    colorScheme: 'dark',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    // Build first: `preview` only serves whatever is already in dist/. Without the
    // build, a failed compile leaves the previous good bundle on disk and the suite
    // passes green against source that no longer compiles, which silently
    // invalidates mutation checking. Building here makes a broken source abort the run.
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}${BASE}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
