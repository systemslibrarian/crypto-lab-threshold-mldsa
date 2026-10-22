import { test, expect } from '@playwright/test';

test('research comparison preserves the fault model and demo boundary', async ({ page }) => {
  await page.goto('.');
  const note = page.locator('#fault-replay-research');
  await expect(note).toBeVisible();
  await expect(note.locator('a')).toHaveAttribute('href', 'https://eprint.iacr.org/2026/2566');
  await expect(note).toContainText('21 October 2026');
  await expect(note).toContainText('preprint');
  await expect(note).toContainText('forced cross-session sample replay');
  await expect(note).toContainText('coordinator-visible per-party responses');
  await expect(note).toContainText('individual signatures still verify');
  await expect(note).toContainText('different evidence levels');
  await expect(note).toContainText('Neither this lab');
  await expect(note).toContainText('implements Mithril or reproduces this attack');
});
