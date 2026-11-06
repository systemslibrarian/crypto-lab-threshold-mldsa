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

// THED author version: §5.3 p.12 and Appendix A.5 p.16.
for (const width of [1280, 380]) {
  test(`THED compatibility separates author claim from tested scope at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('.');
    const row = page.getByRole('row').filter({ hasText: 'THED (2026/638)' });
    await expect(row.getByRole('cell').last()).toContainText('Claimed; reference Dilithium tested');
    await row.getByRole('link', { name: 'THED compatibility evidence' }).click();
    const note = page.locator('#thed-compatibility');
    await expect(note).toBeVisible();
    await expect(note.locator('a')).toHaveAttribute('href', 'https://eprint.iacr.org/2026/638');
    await expect(note).toContainText('claim verification interchangeability with Dilithium/ML-DSA');
    await expect(note).toContainText('NIST level-2');
    await expect(note).toContainText('produced signatures pass reference Dilithium verification');
    await expect(note).toContainText('does not pin the tested verifier revision');
    await expect(note).toContainText('Final FIPS 204 interoperability');
    await expect(note).toContainText('not established by those tests');
    await expect(note).toContainText('not a finding of incompatibility');
    await expect(note).toContainText('does not implement THED');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
}
