import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
// @ts-expect-error -- plain JavaScript build tool without type declarations
import { cspViolations, extensionIdFromKey, manifestReferences, manifestSecurityProblems, parseCsp, PINNED_EXTENSION_ID } from '../tools/build-extension.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.join(ROOT, 'app', 'src');

function sourceFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(full);
    return /\.(ts|tsx)$/.test(entry.name) ? [full] : [];
  });
}

test('manifest: MV3, minimal permissions, every referenced file is built', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.version, pkg.version);
  assert.deepEqual([...manifest.permissions].sort(), ['contextMenus', 'storage']);
  assert.deepEqual(manifest.host_permissions, ['http://127.0.0.1/*', 'http://localhost/*']);
  assert.equal(manifest.background.type, 'module');
  assert.doesNotMatch(manifest.content_security_policy.extension_pages, /unsafe|https:|\*\.|(^|\s)\*(\s|;|$)/);
  assert.deepEqual(manifest.sandbox.pages, ['frame-host.html']);
  assert.deepEqual(
    manifestReferences(manifest).sort(),
    ['background.js', 'frame-host.html', 'icons/icon-128.png', 'icons/icon-16.png', 'icons/icon-48.png', 'options.html'],
  );
});

test('CSP checker flags inline scripts and handlers only', () => {
  assert.deepEqual(cspViolations('<script type="module" src="./a.js"></script>'), []);
  assert.deepEqual(cspViolations('<script>alert(1)</script>'), ['inline <script>']);
  assert.deepEqual(cspViolations('<button onclick="x()">'), ['inline event handler attribute']);
  assert.deepEqual(cspViolations('<a href="javascript:void 0">'), ['javascript: URL']);
});

test('networking audit: every /api path goes through the configured base', () => {
  const apiModules = new Set(['api.ts', 'doctorApi.ts', 'emailMetricsApi.ts']);
  for (const file of sourceFiles(SRC)) {
    const name = path.relative(SRC, file).split(path.sep).join('/');
    // Comments may mention /api paths; only code matters.
    const text = fs.readFileSync(file, 'utf8')
      .split('\n')
      .filter((line) => !/^\s*(\*|\/\/|\/\*)/.test(line))
      .join('\n');
    if (!apiModules.has(name)) {
      assert.doesNotMatch(text, /['"`]\/api\//, `${name} builds a relative /api URL itself`);
    }
    for (const match of text.matchAll(/\bfetch\(([^,)]*)/g)) {
      const target = match[1].trim();
      const allowed = target.startsWith('apiUrl(') || target === 'url'
        || target.startsWith('doctorApi.fileUrl(') || target.startsWith('`${url}/api/health`');
      assert.ok(allowed, `${name}: fetch(${target}) must use apiUrl() or an absolute backend URL`);
    }
  }
  // URL builders used for links/downloads return absolute URLs.
  const api = fs.readFileSync(path.join(SRC, 'api.ts'), 'utf8');
  for (const builder of ['messageEmlUrl', 'attachmentUrl', 'trashArchiveUrl']) {
    assert.match(api, new RegExp(`${builder}: \\([^)]*\\) =>\\s*apiUrl\\(`), `${builder} must wrap apiUrl()`);
  }
  const doctor = fs.readFileSync(path.join(SRC, 'doctorApi.ts'), 'utf8');
  assert.match(doctor, /fileUrl: [^\n]*\n\s*apiUrl\(/);
  assert.match(doctor, /zipUrl: \(id: string\) => apiUrl\(/);
});

test('backend downloads never rely on cross-origin <a download>', () => {
  for (const file of sourceFiles(path.join(SRC, 'components'))) {
    const text = fs.readFileSync(file, 'utf8');
    for (const match of text.matchAll(/<a\b[^>]*\bhref=\{(api\.\w+Url|doctorApi\.\w+Url|fileUrl)\([\s\S]*?<\/a>/g)) {
      assert.match(match[0], /backendDownloadClick/, `${path.basename(file)}: ${match[1]} link needs backendDownloadClick`);
    }
    if (path.basename(file) !== 'SandboxFrame.tsx') {
      assert.doesNotMatch(text, /<iframe[^>]*srcDoc/, `${path.basename(file)}: use SandboxFrame for srcDoc content`);
    }
  }
});

test('manifest key pins the extension id the backend accepts by default', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  assert.equal(PINNED_EXTENSION_ID, 'hhhanbkdjaecdfoclhpoicmfhejdbkjl');
  assert.equal(extensionIdFromKey(manifest.key), PINNED_EXTENSION_ID);
  assert.deepEqual(manifestSecurityProblems(manifest), []);
  assert.match(manifestSecurityProblems({ ...manifest, key: undefined }).join(), /"key" is missing/);
  // A different key (here: the same bytes shifted) gives a different id.
  assert.match(manifestSecurityProblems({ ...manifest, key: `AA${manifest.key}` }).join(), /expected hhhanbkdjaecdfoclhpoicmfhejdbkjl/);
});

test('extension page CSP: loopback-only connect-src, local images, own frames, no form posts', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const csp = parseCsp(manifest.content_security_policy.extension_pages);
  assert.deepEqual(csp['script-src'], ["'self'"]);
  // Chrome ignores IPv6 literals such as http://[::1]:* in CSP (logged as an error).
  assert.deepEqual(csp['connect-src'], ["'self'", 'http://127.0.0.1:*', 'http://localhost:*']);
  assert.doesNotMatch(manifest.content_security_policy.extension_pages, /\[/);
  assert.deepEqual(csp['img-src'], ["'self'", 'data:', 'blob:']);
  assert.deepEqual(csp['frame-src'], ["'self'"]);
  assert.deepEqual(csp['form-action'], ["'none'"]);
  // connect-src origins match the host permissions (same hosts, http only).
  const hosts = manifest.host_permissions.map((pattern: string) => pattern.replace(/\/\*$/, ':*'));
  assert.deepEqual(csp['connect-src'].slice(1), hosts);
  // Weakening the policy is caught by the build.
  const weakened = { ...manifest, content_security_policy: { ...manifest.content_security_policy, extension_pages: "script-src 'self'; connect-src *" } };
  assert.ok(manifestSecurityProblems(weakened).some((problem: string) => problem.includes('connect-src')));
});
