import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Unit tests only. The Playwright a11y suite lives in e2e/ and is run via
    // `npm run test:a11y`, never collected by vitest.
    include: ['test/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
