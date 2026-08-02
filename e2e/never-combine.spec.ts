import { expect, test } from '@playwright/test';

/**
 * Blocking browser regressions for the never-combine toy protocol.
 *
 * Every assertion here is about a computed outcome: the verdict card carries a
 * data-ideal-verdict attribute set from the run's own result, and the norms
 * printed on screen are parsed back out and re-checked against the bounds.
 *
 * Margin: a 300-cycle sweep in Node (each cycle = one DKG, an honest sign, an
 * over-bound tamper, a one-unit tamper and a single-party attempt) was clean,
 * with a mean of 2.52 signing attempts and a worst case of 12 against the
 * 60-attempt budget. The chance of the honest path failing to converge is
 * therefore around 6e-12 per run.
 */

const PER_PARTY_BOUND = 4080;
const Z_BOUND = 8160;

async function openIdeal(page: import('@playwright/test').Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('#contrast-ideal')).toBeVisible();
  await page.locator('#contrast-ideal').click();
  await expect(page.locator('#ideal-stage')).toBeVisible();
  await expect(page.locator('#ideal-verdict')).toContainText('no verdict is claimed');
}

test('running the protocol produces a signature its own verifier accepts', async ({ page }) => {
  await openIdeal(page);
  await page.locator('#ideal-play').click();

  const verdict = page.locator('[data-ideal-verdict]').first();
  await expect(verdict).toHaveAttribute('data-ideal-verdict', 'accepted', { timeout: 30_000 });
  await expect(verdict).toContainText('Toy verifier ACCEPTS');

  // The norms shown are real and inside the bound the page states.
  const text = (await verdict.textContent()) ?? '';
  const zNorm = Number(/‖z‖∞ = (\d+)/.exec(text)?.[1]);
  expect(Number.isFinite(zNorm)).toBe(true);
  expect(zNorm).toBeLessThan(Z_BOUND);
  expect(text).toContain('reproduced c — pass');

  // The never-combined claim is presented as a second, separate verdict.
  await expect(page.locator('[data-ideal-verdict="never-combined"]')).toContainText(
    'Secret never combined',
  );
  await expect(page.locator('#ideal-keybuf')).toContainText('NEVER ASSEMBLED');

  // The attempt trace is a real rejection-sampling record: exactly one accepted
  // attempt, and it is the last one.
  const rows = page.locator('#ideal-attempts .abort-row');
  await expect(rows.first()).toBeVisible();
  const accepted = page.locator('#ideal-attempts .abort-accept');
  await expect(accepted).toHaveCount(1);
  await expect(rows.last()).toHaveClass(/abort-accept/);
  const acceptedText = (await accepted.textContent()) ?? '';
  const norms = [...acceptedText.matchAll(/‖z\^[SP]‖∞ = (\d+)/g)].map((m) => Number(m[1]));
  expect(norms).toHaveLength(2);
  for (const norm of norms) expect(norm).toBeLessThan(PER_PARTY_BOUND);

  // The walkthrough animated the values the run produced, not a script.
  await expect(page.locator('#ideal-channel-slot .ideal-chip-accept')).toContainText(
    'VERIFIER ACCEPTS',
  );
});

test('an over-bound z-share is stopped by the norm check before anything is published', async ({
  page,
}) => {
  await openIdeal(page);
  await page.locator('#ideal-tamper-norm').click();

  const verdict = page.locator('[data-ideal-verdict]').first();
  await expect(verdict).toHaveAttribute('data-ideal-verdict', 'norm-rejected', { timeout: 30_000 });
  await expect(verdict).toContainText('Norm check rejected the phone share');
  await expect(verdict).toContainText('No signature was produced, so there is nothing to verify');

  // The rejected norm really is over the bound.
  const text = (await verdict.textContent()) ?? '';
  const rejectedNorm = Number(/‖z‖∞ = (\d+)/.exec(text)?.[1]);
  expect(rejectedNorm).toBeGreaterThanOrEqual(PER_PARTY_BOUND);

  // No acceptance is claimed anywhere on the panel.
  await expect(page.locator('[data-ideal-verdict="accepted"]')).toHaveCount(0);
  await expect(page.locator('[data-ideal-verdict="never-combined"]')).toHaveCount(0);
  await expect(page.locator('#ideal-channel-slot .ideal-chip-reject')).toContainText(
    'NORM CHECK REJECTED',
  );
});

test('a one-unit corruption slips past the norm check and the verifier catches it', async ({
  page,
}) => {
  await openIdeal(page);
  await page.locator('#ideal-tamper-nudge').click();

  const verdict = page.locator('[data-ideal-verdict]').first();
  await expect(verdict).toHaveAttribute('data-ideal-verdict', 'challenge', { timeout: 30_000 });
  await expect(verdict).toContainText('Toy verifier REJECTS');

  const text = (await verdict.textContent()) ?? '';
  // The lesson: the norm check passed, and only Fiat–Shamir noticed.
  expect(text).toContain('pass');
  expect(text).toContain('did NOT reproduce c — FAIL');
  const zNorm = Number(/‖z‖∞ = (\d+)/.exec(text)?.[1]);
  expect(zNorm).toBeLessThan(Z_BOUND);
  expect(text).toMatch(/a single unit/);
});

test('the panel states its toy scale and does not claim FIPS 204 for it', async ({ page }) => {
  await openIdeal(page);
  const note = page.locator('.toy-scale-note');
  await expect(note).toContainText('no security');
  await expect(note).toContainText('not FIPS 204');
  await expect(note).toContainText('n = 64');
  await expect(note).toContainText('It has its own verifier');
});

test('recovering from a failed run restores a real accepted signature', async ({ page }) => {
  await openIdeal(page);
  await page.locator('#ideal-tamper-norm').click();
  await expect(page.locator('[data-ideal-verdict]').first()).toHaveAttribute(
    'data-ideal-verdict',
    'norm-rejected',
    { timeout: 30_000 },
  );
  await page.locator('#ideal-play').click();
  await expect(page.locator('[data-ideal-verdict]').first()).toHaveAttribute(
    'data-ideal-verdict',
    'accepted',
    { timeout: 30_000 },
  );
});
