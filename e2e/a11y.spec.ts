import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven through every state a reader can actually reach: real
 * ML-DSA-65 key generation awaited, both skip links focused, the share-combine
 * widget revealed and re-hidden, all six steps of the round trace walked and
 * BOTH of the verdicts it can land on reached, the trace returned to its empty
 * state, the aborts micro-demo re-run until its trace holds both a rejected and
 * an accepted attempt, both glossaries opened, the escrow key buffer read with
 * its MATERIALIZED flag, the never-combine toy protocol executed honestly and
 * then tampered with in both of its two ways, a real signature produced, the
 * benchmark run, the phone disabled and the drop-one refusal driven, and the
 * phone restored. Every one of those states is scanned, in both themes, at
 * desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why each scan
 * asserts its content first, and why `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expectBaselineNotStale();
  });
}
