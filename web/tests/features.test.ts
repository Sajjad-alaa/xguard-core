import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

// XGuard has no license tiers: every feature is available, so nothing may lock a feature
// behind a plan or advertise one.

const webRoot = join(__dirname, '..');

const files = (dir: string, extensions: string[]): string[] =>
  readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    // The UI kit submodule is shared with other XGuard apps and has no plan copy.
    if (name === 'node_modules' || name === 'xguard-ui') return [];
    if (statSync(path).isDirectory()) return files(path, extensions);
    return extensions.some((extension) => name.endsWith(extension)) ? [path] : [];
  });

const upsell =
  /upgrade (your|to)[^.]*\b(plan|business|enterprise)\b|(business|enterprise|paid|higher) plans?\b|pricing|enterprise feature|higher license tier/i;

describe('XGuard feature availability (no license tiers)', () => {
  it('has no upsell, plan or pricing copy in the English messages', () => {
    const offenders = files(join(webRoot, 'messages', 'en'), ['.json']).flatMap((path) =>
      Object.entries(JSON.parse(readFileSync(path, 'utf8')) as Record<string, string>)
        .filter(
          ([key, value]) => upsell.test(value) || /^(license|limit_reached)_/.test(key),
        )
        .map(([key]) => `${relative(webRoot, path)}: ${key}`),
    );
    expect(offenders).toEqual([]);
  });

  it('has no license gates or pricing links in the sources', () => {
    const offenders = files(join(webRoot, 'src'), ['.ts', '.tsx']).filter((path) =>
      /utils\/license|canUse(Business|Enterprise)Feature|LicenseFeature\b|\.pricing\b/.test(
        readFileSync(path, 'utf8'),
      ),
    );
    expect(offenders.map((path) => relative(webRoot, path))).toEqual([]);
  });

  it('offers "Allowed IPs from firewall rules" when adding and editing a location', () => {
    for (const page of [
      'src/pages/AddLocationPage/steps/AddLocationInternalVpnStep.tsx',
      'src/pages/EditLocationPage/EditLocationPage.tsx',
    ]) {
      const source = readFileSync(join(webRoot, page), 'utf8');
      const start = source.indexOf('name="allowed_ips_from_acl"');
      expect(start, page).toBeGreaterThan(0);
      const field = source.slice(start, source.indexOf('</form.AppField>', start));
      // The checkbox is never disabled and has no upsell next to it.
      expect(field, page).not.toMatch(/disabled=/);
      expect(source, page).not.toMatch(/upsell/);
    }
  });
});
