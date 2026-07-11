import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * Strict WCAG regression gate for the Threshold ML-DSA lab.
 *
 * The app is a single-page demo rendered by main.ts (no tabs, no <details>).
 * It has three live buttons — Start threshold signing, Disable phone, Run quick
 * benchmark — each of which rewrites the status banner, the stats grid and the
 * protocol log with dynamically-injected result markup. So we DRIVE those demos
 * (both the drop-one/disabled path and the full signing + benchmark paths) so
 * every injected result region is in the DOM and painted when axe runs.
 *
 * Scans both themes with WCAG 2.0/2.1 A + AA rules; asserts zero violations.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Neutralize animation/transition/opacity so mid-flight states (button hover
// lift, disabled fade) can't hide text from the contrast checker.
async function killMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation-duration:0s!important;animation-delay:0s!important;
      transition-duration:0s!important;transition-delay:0s!important;
      opacity:1!important;scroll-behavior:auto!important;
    }`,
  });
}

// Generic collapsible expansion for robustness (this lab has none today).
async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const d of document.querySelectorAll('details')) (d as HTMLDetailsElement).open = true;
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) el.removeAttribute('hidden');
  });
}

// Drive every live demo so injected result regions (log rows, stat cards,
// status tones) exist and are painted during the scan.
async function driveDemos(page: Page): Promise<void> {
  // Full 2-of-2 signing run: rewrites the protocol log with round rows and the
  // stats grid with a PASS/FAIL verifier cell.
  await page.locator('#sign-button').click();
  await expect(page.locator('#protocol-log .log-row').first()).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('#sign-button')).toBeEnabled({ timeout: 60_000 });

  // Benchmark run: injects the log-ok result row and benchmark stats.
  await page.locator('#benchmark-button').click();
  await expect(page.locator('#protocol-log .log-ok')).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('#benchmark-button')).toBeEnabled({ timeout: 60_000 });

  // Drop-one path: disable the phone and attempt to sign so the log-reject
  // "2-of-2 enforced" region and warning-tone banner render.
  await page.locator('#phone-toggle').click();
  await expect(page.locator('#phone-toggle')).toHaveAttribute('aria-pressed', 'true');
  await page.locator('#sign-button').click();
  await expect(page.locator('#protocol-log .log-reject')).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('#sign-button')).toBeEnabled({ timeout: 60_000 });

  // Restore the phone so the enabled/idle styling is also covered.
  await page.locator('#phone-toggle').click();
  await expect(page.locator('#phone-toggle')).toHaveAttribute('aria-pressed', 'false');
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#cl-theme-toggle')).toBeVisible();
  await expect(page.locator('#sign-button')).toBeVisible();
  await killMotion(page);
});

test('no WCAG A/AA violations in dark theme (all demos driven)', async ({ page }) => {
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await driveDemos(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme (all demos driven)', async ({ page }) => {
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await driveDemos(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});
