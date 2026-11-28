#!/usr/bin/env node
/**
 * Assemble the load-unpacked extension folder from the Vite output.
 *
 *   npm run build:extension      (typecheck + vite build + this script)
 *   node tools/build-extension.mjs [--out DIR]
 *
 * Inputs : app/dist (vite build), manifest.json, icons/ (generated if missing)
 * Output : dist/ (default) with manifest.json, index.html, options.html,
 *          frame-host.html/.js, background.js, assets/, icons/
 *
 * Checks : manifest/package versions match, every file the manifest names
 *          exists, the service worker's imports resolve, no extension page
 *          contains inline scripts or inline event handlers (MV3 CSP), the
 *          manifest "key" is present and still pins the extension id
 *          (PINNED_EXTENSION_ID; the backend's default Origin allow-list), the
 *          extension_pages CSP keeps its hardening directives, and the built
 *          manifest is byte-for-byte the source manifest (so "key" ships).
 *
 * The output folder is only emptied when it carries this script's marker
 * file, so a mistyped --out never wipes an unrelated directory.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ICON_SIZES, writeIcons } from './gen-icons.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const APP_DIST = path.join(ROOT, 'app', 'dist');
const ICONS = path.join(ROOT, 'icons');
const MARKER = '.webmail-extension-build';

/**
 * Extension id derived from manifest.json "key". mail-backend accepts only
 * `chrome-extension://<this id>` by default (MAIL_BACKEND_EXTENSION_IDS
 * overrides it), so changing the key needs a matching backend setting.
 */
export const PINNED_EXTENSION_ID = 'hhhanbkdjaecdfoclhpoicmfhejdbkjl';

/** Directives the extension_pages CSP must contain, exactly as listed. */
export const REQUIRED_PAGE_CSP = {
  'script-src': ["'self'"],
  'img-src': ["'self'", 'data:', 'blob:'],
  'frame-src': ["'self'"],
  'form-action': ["'none'"],
  // No http://[::1]:* -- Chrome rejects IPv6 literals in CSP source lists.
  'connect-src': ["'self'", 'http://127.0.0.1:*', 'http://localhost:*'],
};

/**
 * Chrome/Edge extension id for a manifest "key" (base64 DER SubjectPublicKeyInfo):
 * the first 128 bits of SHA-256(key bytes), each hex digit mapped 0-f -> a-p.
 */
export function extensionIdFromKey(key) {
  const digest = crypto.createHash('sha256').update(Buffer.from(String(key), 'base64')).digest('hex');
  return [...digest.slice(0, 32)].map((digit) => String.fromCharCode(97 + parseInt(digit, 16))).join('');
}

/** Parse a CSP string into { directive: [sources] }. */
export function parseCsp(policy) {
  const directives = {};
  for (const part of String(policy ?? '').split(';')) {
    const [name, ...sources] = part.trim().split(/\s+/).filter(Boolean);
    if (name) directives[name.toLowerCase()] = sources;
  }
  return directives;
}

/** Problems with the manifest's pinned id and page CSP (empty when fine). */
export function manifestSecurityProblems(manifest) {
  const problems = [];
  if (typeof manifest.key !== 'string' || !manifest.key) {
    problems.push('manifest "key" is missing (it pins the extension id the backend accepts)');
  } else if (extensionIdFromKey(manifest.key) !== PINNED_EXTENSION_ID) {
    problems.push(`manifest "key" gives extension id ${extensionIdFromKey(manifest.key)}, expected ${PINNED_EXTENSION_ID}`);
  }
  const csp = parseCsp(manifest.content_security_policy?.extension_pages);
  for (const [directive, sources] of Object.entries(REQUIRED_PAGE_CSP)) {
    const actual = csp[directive] ?? [];
    if (actual.length !== sources.length || sources.some((source) => !actual.includes(source))) {
      problems.push(`extension_pages CSP ${directive} must be "${sources.join(' ')}", got "${actual.join(' ')}"`);
    }
  }
  return problems;
}

function parseArgs(argv) {
  const options = { out: path.join(ROOT, 'dist') };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--out') {
      const value = argv[index + 1];
      if (!value) throw new Error('--out needs a directory');
      options.out = path.resolve(value);
      index += 1;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  return options;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function listFiles(dir, base = dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listFiles(full, base));
    else if (entry.isFile()) out.push(path.relative(base, full).split(path.sep).join('/'));
  }
  return out.sort();
}

function prepareOutDir(out) {
  if (fs.existsSync(out)) {
    const entries = fs.readdirSync(out);
    if (entries.length && !entries.includes(MARKER)) {
      throw new Error(`${out} is not empty and was not created by this script; refusing to overwrite it`);
    }
    fs.rmSync(out, { recursive: true, force: true });
  }
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, MARKER), 'Generated by tools/build-extension.mjs; safe to delete.\n');
}

/** Files the manifest points at; each must exist in the package. */
export function manifestReferences(manifest) {
  const refs = new Set();
  const addIcons = (icons) => {
    if (icons && typeof icons === 'object') Object.values(icons).forEach((value) => refs.add(value));
  };
  addIcons(manifest.icons);
  addIcons(manifest.action?.default_icon);
  if (manifest.action?.default_popup) refs.add(manifest.action.default_popup);
  if (manifest.options_ui?.page) refs.add(manifest.options_ui.page);
  if (manifest.options_page) refs.add(manifest.options_page);
  if (manifest.background?.service_worker) refs.add(manifest.background.service_worker);
  for (const page of manifest.sandbox?.pages ?? []) refs.add(page);
  return [...refs].map((ref) => ref.replace(/^\//, ''));
}

/** Inline <script> bodies and on*= handler attributes violate the MV3 CSP. */
export function cspViolations(html) {
  const problems = [];
  for (const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    if (!/\bsrc\s*=/.test(match[1]) || match[2].trim()) problems.push('inline <script>');
  }
  if (/<[a-z][^>]*\son[a-z]+\s*=/i.test(html)) problems.push('inline event handler attribute');
  if (/\bjavascript:/i.test(html)) problems.push('javascript: URL');
  return problems;
}

function checkPackage(out, manifest) {
  const files = new Set(listFiles(out));
  const missing = manifestReferences(manifest).filter((ref) => !files.has(ref));
  if (missing.length) throw new Error(`manifest references missing files: ${missing.join(', ')}`);

  for (const file of files) {
    if (!file.endsWith('.html')) continue;
    const problems = cspViolations(fs.readFileSync(path.join(out, file), 'utf8'));
    if (problems.length) throw new Error(`${file} violates the extension CSP: ${problems.join(', ')}`);
  }

  const worker = manifest.background.service_worker;
  const source = fs.readFileSync(path.join(out, worker), 'utf8');
  for (const match of source.matchAll(/\bfrom\s*["'](\.{1,2}\/[^"']+)["']/g)) {
    const target = path.posix.normalize(path.posix.join(path.posix.dirname(worker), match[1]));
    if (!files.has(target)) throw new Error(`${worker} imports missing ${target}`);
  }
  return files;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const pkg = readJson(path.join(ROOT, 'package.json'));
  const manifest = readJson(path.join(ROOT, 'manifest.json'));
  if (manifest.manifest_version !== 3) throw new Error(`manifest_version must be 3, got ${manifest.manifest_version}`);
  if (manifest.version !== pkg.version) {
    throw new Error(`manifest.json version ${manifest.version} does not match package.json version ${pkg.version}`);
  }
  if (!fs.existsSync(path.join(APP_DIST, 'index.html'))) {
    throw new Error('app/dist/index.html is missing; run "npm run build" first');
  }
  const security = manifestSecurityProblems(manifest);
  if (security.length) throw new Error(security.join('; '));
  if (ICON_SIZES.some((size) => !fs.existsSync(path.join(ICONS, `icon-${size}.png`)))) writeIcons(ICONS);

  prepareOutDir(options.out);
  fs.cpSync(APP_DIST, options.out, { recursive: true });
  fs.cpSync(ICONS, path.join(options.out, 'icons'), { recursive: true });
  fs.writeFileSync(path.join(options.out, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);

  const files = checkPackage(options.out, manifest);
  const built = readJson(path.join(options.out, 'manifest.json'));
  if (JSON.stringify(built) !== JSON.stringify(manifest) || built.key !== manifest.key) {
    throw new Error('dist/manifest.json differs from manifest.json');
  }
  console.log(`Extension ${manifest.name} ${manifest.version}: ${files.size} files in ${path.relative(process.cwd(), options.out) || '.'}`);
  console.log(`Extension id (from manifest "key"): ${extensionIdFromKey(manifest.key)}`);
  console.log('Load it via chrome://extensions or edge://extensions > Developer mode > Load unpacked.');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (failure) {
    console.error(`build-extension: ${failure instanceof Error ? failure.message : failure}`);
    process.exit(1);
  }
}
