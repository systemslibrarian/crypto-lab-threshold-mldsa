import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText, formatNonTextFailures, type NonTextFailure } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The gate this replaced
 *     pushed `*{opacity:1!important}` through `addStyleTag` before every scan,
 *     which is why it was green: it erased `.ideal-keybuf`'s `opacity:.6` and
 *     handed axe a foreground the compositor never paints.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over an empty container passes having checked
 *     nothing, and at first paint this lab is very nearly empty: the round
 *     trace shows one placeholder sentence where six steps of lane chips will
 *     go, the aborts view says "No round run yet", the protocol log says
 *     "Awaiting the first signing run…", both verdict cards read "awaiting
 *     run", the share-combine widget shows "—" and "?", and the never-combine
 *     panel does not exist in the DOM at all until its toggle is pressed. The
 *     lab's whole argument — that this build earns custody but NOT
 *     key-non-reconstruction, and that the toy path earns the reverse — is
 *     carried by ink that only exists after those states are driven: the red
 *     MATERIALIZED IN MEMORY flag, the green NEVER ASSEMBLED flag, the
 *     accept/reject chips, the four verdict-card tones and the per-attempt
 *     rejection trace.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab is
 * a live candidate: `trace-pop` starts at `opacity: .2` and every newly revealed
 * trace chip runs it, so a reduced-motion block that cancelled the animation
 * outright rather than collapsing its duration would strand those chips faded.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. That assertion is not ceremony here: the two
 * chip-flight animations and the never-combine step pacing both branch on
 * `matchMedia('(prefers-reduced-motion: reduce)')` at runtime, so an emulation
 * that silently did nothing would leave the gate driving a different app.
 *
 * Distributed key generation is real ML-DSA-65 and runs on load, so `boot`
 * waits for it rather than racing it. The "Initializing the two-party
 * ML-DSA-65 demo…" banner it replaces is genuinely transient, but the same
 * `tone-idle` surface is reachable deterministically later — re-enabling the
 * phone paints it — and the gate scans it there.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  await expect(page.locator('#sign-button')).toBeVisible();
  await expect(page.locator('#cl-theme-toggle')).toBeVisible();
  // Real ML-DSA-65 key generation, split into additive shares, then verified.
  await expect(page.locator('#status-banner')).toHaveClass(/tone-success/, { timeout: 60_000 });
  await expect(page.locator('#server-share-box .masked-row')).toHaveCount(4);
  await expect(page.locator('#share-server-byte')).not.toHaveText('—');
  // The panels that carry the lab's claims are genuinely placeholders here, so
  // a scan at this point proves nothing about them — which is the whole reason
  // `driveAllStates` exists.
  await expect(page.locator('#share-result-byte')).toHaveText('?');
  await expect(page.locator('.trace-placeholder')).toBeVisible();
  await expect(page.locator('#sign-verdict .verdict-idle')).toHaveCount(2);
  await expect(page.locator('#ideal-stage')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it lays the signing stage on a three-column grid, the
 * round trace and the never-combine stage on two more, the guided path on a
 * five-column one, and it prints a five-column research table and monospace
 * polynomial dumps (`[ 12, -3, 45]`) inside them. Every track is written
 * `minmax(0, …)` precisely so this assertion holds; a bare `1fr` anywhere would
 * put a min-content floor back under a column and break it.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide table inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That
    // cost a run elsewhere in this fleet (a 980px table was reported while the
    // real overflow was 15px of something else), and this lab has exactly that
    // decoy: the five-column research landscape table inside `.table-wrap`.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Assert a revealed element is wholly on screen and wholly unclipped.
 *
 * Neither axe nor the contrast oracle has anything to say about this, and both
 * are content to measure a box whose right-hand third is not painted. This lab
 * has no popovers or tooltips today, so the oracle is pointed at the four
 * elements whose whole job is to be *read*: the red MATERIALIZED IN MEMORY flag
 * on the escrow key buffer, the green NEVER ASSEMBLED flag on the toy path's
 * key buffer, and the accept/reject chips the trace and the never-combine round
 * land on. Each of those is the punchline of the exhibit it sits in, each sits
 * several boxes deep inside a panel, and a `overflow: hidden` added anywhere up
 * that chain would cut them without failing any other assertion here.
 */
export async function expectNotClipped(
  page: Page,
  selector: string,
  label: string
): Promise<void> {
  // Measure the settled frame, the same one `scan` measures — a chip placed by
  // the flight animation is not necessarily in its final position on the frame
  // it appeared.
  await settle(page);
  const cut = await page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) return `no element matched ${sel}`;
    const b = el.getBoundingClientRect();
    if (b.width <= 0 || b.height <= 0) return `${sel} has an empty box`;
    const out: string[] = [];
    if (b.left < -0.5 || b.right > window.innerWidth + 0.5) {
      out.push(`outside the viewport (${Math.round(b.left)}..${Math.round(b.right)} of ${window.innerWidth})`);
    }
    for (let n = el.parentElement; n; n = n.parentElement) {
      const cs = getComputedStyle(n);
      if (!/auto|scroll|hidden|clip/.test(cs.overflowX + ' ' + cs.overflowY)) continue;
      const c = n.getBoundingClientRect();
      const lost = Math.max(0, c.left - b.left) + Math.max(0, b.right - c.right) +
        Math.max(0, c.top - b.top) + Math.max(0, b.bottom - c.bottom);
      if (lost > 0.5) {
        out.push(
          `${Math.round(lost)}px clipped by ${n.tagName.toLowerCase()}` +
            `${n.id ? '#' + n.id : ''}.${(n.getAttribute('class') ?? '').trim()}`
        );
      }
    }
    return out.length ? out.join('; ') : null;
  }, selector);
  expect(cut, `${selector} must be fully painted in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  expect(violations, `axe violations in state: ${label}`).toEqual([]);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  expect(unexplainedIncomplete, `axe incomplete results in state: ${label}`).toEqual([]);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  expect(contrast, `measured contrast failures in state: ${label}`).toEqual([]);

  await expectNoNewNonTextFailures(page, label);
  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}

/**
 * Advance the round trace to its final step and report which way it landed.
 *
 * `computeRound` draws fresh randomness every time, so step 6 lands on an
 * ACCEPT chip or a REJECT chip depending on whether `|z|∞` cleared the bound —
 * roughly a 35/65 split at these toy parameters. Those are two different
 * palettes (`--success`-tinted versus `--danger`-tinted) on two different
 * strings, so a gate that only ever saw one of them would be scanning half the
 * exhibit. `scanEach` is off for the re-draws: the intermediate steps are
 * identical between rounds apart from their numbers, so they are scanned once.
 */
async function walkTraceToVerdict(
  page: Page,
  scanAt: (s: string) => Promise<void>,
  scanEach: boolean
): Promise<'accepted' | 'rejected'> {
  const TITLES = [
    'Step 1 — sample nonce shares',
    'Step 2 — commitment w = A·y',
    'Step 3 — high bits w₁',
    'Step 4 — Fiat–Shamir challenge c',
    'Step 5 — responses z = y + c·s₁',
    'Step 6 — infinity-norm check',
  ];
  for (let i = 0; i < TITLES.length; i++) {
    await page.locator('#trace-next').click();
    await expect(page.locator('.trace-step-title')).toHaveText(TITLES[i]);
    if (scanEach) await scanAt(`round trace, ${TITLES[i].toLowerCase()}`);
  }
  const chip = page.locator('#trace-lane-channel-slots .trace-chip').last();
  await expect(chip).toBeVisible();
  const cls = (await chip.getAttribute('class')) ?? '';
  return cls.includes('trace-chip-accept') ? 'accepted' : 'rejected';
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * The page has no tabs and no routing; what it has is eight independent widgets
 * that each start as a placeholder, plus one hard prerequisite that governs
 * three of them — nothing can show a real key byte until distributed key
 * generation finishes, which `boot` waits on. From there the drive walks each
 * widget through every branch it can actually reach:
 *
 *   - the share-combine widget in both of its states, because the revealed
 *     result byte is the only thing on the page painted `--gold-ink` at 1.5rem;
 *   - all six steps of the round trace, and BOTH verdicts it can land on — the
 *     accept and reject chips are different palettes and the drive re-draws
 *     rounds until it has seen each;
 *   - the trace's empty state, which "Fresh randomness (restart)" returns to and
 *     which paints the two `.trace-lane-empty` placeholders;
 *   - the aborts micro-demo, re-run until its trace holds both an accepted and a
 *     rejected attempt row, for the same reason;
 *   - both `<details>` glossaries, opened through their `<summary>` the way a
 *     reader opens them;
 *   - the escrow/never-combine fork in all four of its states: the escrow key
 *     buffer with the red MATERIALIZED flag, and the toy protocol run honestly,
 *     tampered over the norm bound, and tampered by one unit — three genuinely
 *     different verdict cards, one of them the only `verdict-good` the page can
 *     paint;
 *   - live signing, the benchmark, and the drop-one path with the phone
 *     disabled, which is the only route to `log-reject` in the protocol log and
 *     to the `tone-warning` banner;
 *   - the phone restored, which is the only deterministic route back to the
 *     `tone-idle` banner surface.
 *
 * Two banner tones are deliberately not chased. `tone-working` is set and
 * cleared inside a single awaited signing call — asserting it is a race, and it
 * paints `--text` (the body ink) on a 14%-purple wash, which is the same
 * foreground the gate already measures on every panel. `tone-danger` is
 * reachable only from a caught exception in `runSigningDemo` /
 * `runBenchmarkDemo` / `runInitialChecks`, i.e. only if the crypto itself
 * throws; there is no UI route to it, and faking one would be testing a state
 * the app cannot enter. Both are recorded here so the next reader does not add
 * a click that can only hang.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);
  // Real ML-DSA-65 signing and a six-iteration benchmark are main-thread work
  // well past the 20s default that `boot` sets for ordinary clicks.
  const HEAVY = { timeout: 120_000 };

  await scanAt('key generation complete');

  // Both skip links park off-screen until focused, so the focused rendering is
  // the only one that paints. The shared header's is first in the tab order.
  await page.locator('a.cl-skip-link').focus();
  await scanAt('shared skip link focused');
  await page.locator('a.skip-link').focus();
  await scanAt('lab skip link focused');

  // ── Stop 1: the live additive-share combine ───────────────────────────────
  // The result byte is `?` in `--text` until combined and the real key byte in
  // `--gold-ink` after, and the note below it is rewritten with the arithmetic.
  await page.locator('#share-combine-btn').click();
  await expect(page.locator('#share-result-byte')).toHaveClass(/share-byte-revealed/);
  await expect(page.locator('#share-result-byte')).not.toHaveText('?');
  await expect(page.locator('#share-combine-note')).toContainText('mod 256 =');
  await scanAt('share bytes combined, real key byte revealed');

  await page.locator('#share-reroll-btn').click();
  await expect(page.locator('#share-result-byte')).toHaveText('?');
  await scanAt('a different share byte, hidden again');

  // ── Stop 3: the round trace, both verdicts ────────────────────────────────
  const first = await walkTraceToVerdict(page, scanAt, true);
  await scanAt(`round trace, verdict: ${first}`);
  let other: 'accepted' | 'rejected' | null = null;
  for (let i = 0; i < 40 && other === null; i++) {
    await page.locator('#trace-reset').click();
    await expect(page.locator('.trace-placeholder')).toBeVisible();
    const got = await walkTraceToVerdict(page, scanAt, false);
    if (got !== first) other = got;
  }
  expect(other, 'the round trace must reach both an accept and a reject verdict').not.toBeNull();
  await expectNotClipped(
    page,
    '#trace-lane-channel-slots .trace-chip:last-child',
    `${theme} / round trace verdict: ${other}`
  );
  await scanAt(`round trace, verdict: ${other}`);

  // Steps 3 and 4 put chips only in the channel, so the SERVER and PHONE lanes
  // render their `—` placeholder there; the first walk above scanned both.
  await page.locator('#trace-reset').click();
  await expect(page.locator('.trace-placeholder')).toBeVisible();
  await expect(page.locator('.trace-lane-empty')).toHaveCount(0);
  await scanAt('round trace reset to its empty state');

  // ── Stop 2: the aborts micro-demo ─────────────────────────────────────────
  // Re-run until the trace holds both an accepted and a rejected attempt: the
  // two rows are different palettes and a run that converged first try paints
  // only one of them.
  for (let i = 0; i < 40; i++) {
    await page.locator('#aborts-run').click();
    await expect(page.locator('#aborts-view .abort-row').first()).toBeVisible();
    const rejects = await page.locator('#aborts-view .abort-reject').count();
    const accepts = await page.locator('#aborts-view .abort-accept').count();
    if (rejects > 0 && accepts > 0) break;
  }
  await expect(page.locator('#aborts-view .abort-reject').first()).toBeVisible();
  await expect(page.locator('#aborts-view .abort-accept')).toHaveCount(1);
  await scanAt('aborts trace: rejected attempts, then one accepted');

  // ── Both glossaries, opened the way a reader opens them ───────────────────
  // A closed <details> hides its body with `content-visibility: hidden`, so its
  // sixteen definition pairs are invisible to every scan until this happens.
  const glossaries = page.locator('details.glossary');
  await expect(glossaries).toHaveCount(2);
  for (let i = 0; i < 2; i++) {
    await glossaries.nth(i).locator('summary').click();
    await expect(glossaries.nth(i)).toHaveAttribute('open', '');
  }
  await expect(page.locator('details.glossary[open] .glossary-list dt').first()).toBeVisible();
  await scanAt('both glossaries open');

  // ── Stop 4: escrow vs. never-combine ──────────────────────────────────────
  // Escrow is the default view. Its key buffer only holds real hex once DKG has
  // run, and `boot` waited for that, so this is the populated form.
  await expect(page.locator('#contrast-view .contrast-key-live')).toBeVisible();
  await expect(page.locator('.contrast-key-live .contrast-flag')).toHaveText(
    /MATERIALIZED IN MEMORY/
  );
  await expect(page.locator('.contrast-key-live code')).not.toContainText('generating key');
  await expectNotClipped(
    page,
    '.contrast-key-live .contrast-flag',
    `${theme} / escrow key buffer materialized`
  );
  await scanAt('escrow view: the key buffer materialized');

  await page.locator('#contrast-ideal').click();
  await expect(page.locator('#contrast-ideal')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#ideal-stage')).toBeVisible();
  await expect(page.locator('#ideal-verdict')).toContainText('no verdict is claimed');
  await expectNotClipped(
    page,
    '#ideal-keybuf .contrast-flag-ok',
    `${theme} / never-combine panel before any run`
  );
  await scanAt('never-combine panel, before any run');

  // The toy two-party protocol actually executes; every value rendered comes out
  // of the run. Wait on the verdict the run produced, not on a timeout.
  await page.locator('#ideal-play').click();
  await expect(page.locator('[data-ideal-verdict="accepted"]')).toBeVisible(HEAVY);
  await expect(page.locator('[data-ideal-verdict="never-combined"]')).toBeVisible();
  await expect(page.locator('#ideal-channel-slot .ideal-chip-accept')).toBeVisible();
  await expect(page.locator('#ideal-play')).toBeEnabled();
  await expect(page.locator('#ideal-attempts .abort-row').first()).toBeVisible();
  await expectNotClipped(
    page,
    '#ideal-channel-slot .ideal-chip-accept',
    `${theme} / never-combine round accepted`
  );
  await scanAt('never-combine round accepted by its own verifier');

  // Over-bound tamper: the norm check catches it before anything is published,
  // so there is no signature and no verifier verdict — a different card.
  await page.locator('#ideal-tamper-norm').click();
  await expect(page.locator('[data-ideal-verdict="norm-rejected"]')).toBeVisible(HEAVY);
  await expect(page.locator('#ideal-channel-slot .ideal-chip-reject')).toBeVisible();
  await expect(page.locator('#ideal-tamper-norm')).toBeEnabled();
  await scanAt("never-combine round: phone's z-share pushed over the bound");

  // One-unit tamper: the norm check waves it through and only the Fiat–Shamir
  // recomputation notices. This is the branch the exhibit exists to show.
  await page.locator('#ideal-tamper-nudge').click();
  await expect(page.locator('[data-ideal-verdict="challenge"]')).toBeVisible(HEAVY);
  await expect(page.locator('#ideal-verdict')).toContainText('did NOT reproduce c');
  await expect(page.locator('#ideal-tamper-nudge')).toBeEnabled();
  await scanAt('never-combine round: one-unit tamper caught by Fiat–Shamir');

  await page.locator('#contrast-escrow').click();
  await expect(page.locator('#contrast-escrow')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#contrast-view .contrast-key-live')).toBeVisible();

  // ── Stop 5: live two-party signing ────────────────────────────────────────
  // Six real ML-DSA-65 steps land in the log, half tagged "Real cryptography"
  // (`log-ok`) and half "Illustrative" (`log-reject`) — two palettes at once.
  await page.locator('#sign-button').click();
  await expect(page.locator('#sign-button')).toBeEnabled(HEAVY);
  await expect(page.locator('#status-banner')).toHaveClass(/tone-warning/);
  await expect(page.locator('#verdict-sig')).toHaveClass(/verdict-good/);
  await expect(page.locator('#verdict-trust')).toHaveClass(/verdict-bad/);
  await expect(page.locator('#protocol-log .log-row').first()).toBeVisible();
  await expect(page.locator('#joint-artifact-text')).toContainText('σ =');
  await scanAt('signed: valid signature, distributed trust NOT achieved');

  await page.locator('#benchmark-button').click();
  await expect(page.locator('#benchmark-button')).toBeEnabled(HEAVY);
  await expect(page.locator('#status-banner')).toHaveClass(/tone-success/);
  await expect(page.locator('#protocol-log .log-ok')).toBeVisible();
  await expect(page.locator('#sign-stats .stat-card')).toHaveCount(6);
  await scanAt('benchmark complete, measured overhead reported');

  // ── The drop-one path ─────────────────────────────────────────────────────
  await page.locator('#phone-toggle').click();
  await expect(page.locator('#phone-toggle')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#status-banner')).toHaveClass(/tone-warning/);
  await expect(page.locator('#phone-indicator')).toHaveClass(/off-dot/);
  await scanAt('phone disabled');

  await page.locator('#sign-button').click();
  await expect(page.locator('#sign-button')).toBeEnabled(HEAVY);
  await expect(page.locator('#protocol-log .log-reject')).toBeVisible();
  await expect(page.locator('#verdict-sig')).toHaveClass(/verdict-bad/);
  await expect(page.locator('#verdict-trust')).toHaveClass(/verdict-good/);
  await expect(page.locator('#joint-artifact-text')).toContainText('Signing blocked');
  await scanAt('drop-one refused: 2-of-2 enforced');

  await page.locator('#phone-toggle').click();
  await expect(page.locator('#phone-toggle')).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('#status-banner')).toHaveClass(/tone-idle/);
  await scanAt('phone restored, idle banner');
}
