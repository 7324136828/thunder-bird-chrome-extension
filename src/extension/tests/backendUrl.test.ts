import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DEFAULT_BACKEND_URL, IPV6_LOOPBACK_ERROR, isLoopbackBackendUrl, LOOPBACK_HTTP_REQUIRED_ERROR, LOOPBACK_REQUIRED_ERROR, normalizeBackendUrl, validateBackendUrl } from '../app/src/platform/backendUrl.ts';

function ok(input: string): string {
  const result = normalizeBackendUrl(input);
  assert.ok(result.ok, `expected ${JSON.stringify(input)} to be accepted`);
  return result.url;
}

function rejected(input: string): string {
  const result = normalizeBackendUrl(input);
  assert.ok(!result.ok, `expected ${JSON.stringify(input)} to be rejected`);
  return result.error;
}

test('default address is the Rust backend port', () => {
  assert.equal(DEFAULT_BACKEND_URL, 'http://127.0.0.1:48101');
  assert.equal(ok(''), DEFAULT_BACKEND_URL);
  assert.equal(ok('   '), DEFAULT_BACKEND_URL);
});

test('adds http:// and strips trailing slashes', () => {
  assert.equal(ok('127.0.0.1:48101'), 'http://127.0.0.1:48101');
  assert.equal(ok('http://localhost:48101/'), 'http://localhost:48101');
  assert.equal(ok('  HTTP://LocalHost:9000///  '), 'http://localhost:9000');
  assert.equal(ok('https://mail.example.test/proxy/'), 'https://mail.example.test/proxy');
  assert.equal(ok('http://[::1]:48101'), 'http://[::1]:48101');
});

test('rejects unsafe or ambiguous addresses', () => {
  assert.match(rejected('ftp://127.0.0.1'), /http:\/\/ or https:\/\//);
  assert.match(rejected('http://user:pw@127.0.0.1:48101'), /user name or password/);
  assert.match(rejected('http://127.0.0.1:48101/?x=1'), /query/);
  assert.match(rejected('http://127.0.0.1:48101/#top'), /fragment/);
  assert.match(rejected('http://127.0.0.1 :48101'), /spaces/);
  assert.match(rejected('http://:48101'), /valid address|host/);
});

test('loopback detection', () => {
  assert.equal(isLoopbackBackendUrl('http://127.0.0.1:48101'), true);
  // Other 127.x addresses: no host permission, and the backend's Host guard refuses them.
  assert.equal(isLoopbackBackendUrl('127.5.6.7:1'), false);
  assert.equal(isLoopbackBackendUrl('http://localhost:48101'), true);
  assert.equal(isLoopbackBackendUrl('http://[::1]:48101'), true);
  assert.equal(isLoopbackBackendUrl(''), true);
  assert.equal(isLoopbackBackendUrl('http://192.168.1.10:48101'), false);
  assert.equal(isLoopbackBackendUrl('http://localhost.example.com'), false);
  assert.equal(isLoopbackBackendUrl('http://127.0.0.1.nip.io'), false);
  assert.equal(isLoopbackBackendUrl('ftp://127.0.0.1'), false);
});

test('saved / used addresses must be loopback', () => {
  assert.deepEqual(validateBackendUrl(''), { ok: true, url: DEFAULT_BACKEND_URL });
  assert.deepEqual(validateBackendUrl('localhost:9000/'), { ok: true, url: 'http://localhost:9000' });
  // [::1] is loopback but cannot be listed in the extension CSP connect-src.
  assert.deepEqual(validateBackendUrl('http://[::1]:48101'), { ok: false, error: IPV6_LOOPBACK_ERROR });
  for (const remote of ['192.168.1.5:1', 'https://mail.example.test/proxy', 'http://127.0.0.1.nip.io', 'http://0.0.0.0:48101', 'http://127.0.0.2:48101']) {
    assert.deepEqual(validateBackendUrl(remote), { ok: false, error: LOOPBACK_REQUIRED_ERROR }, remote);
  }
  // Plain-http remote addresses and https anywhere are refused: connect-src
  // and host_permissions cover only http:// loopback origins.
  for (const remote of ['http://mail.example.test:48101', 'http://10.0.0.2', 'https://mail.example.test']) {
    assert.equal(validateBackendUrl(remote).ok, false, remote);
  }
  for (const tls of ['https://127.0.0.1:48101', 'https://localhost', 'https://[::1]:9']) {
    assert.deepEqual(validateBackendUrl(tls), { ok: false, error: LOOPBACK_HTTP_REQUIRED_ERROR }, tls);
  }
  // Path prefixes on loopback stay allowed (reverse proxy on this computer).
  assert.deepEqual(validateBackendUrl('http://127.0.0.1:8080/mail/'), { ok: true, url: 'http://127.0.0.1:8080/mail' });
  // Syntax errors keep their own message.
  assert.match((validateBackendUrl('http://u:p@127.0.0.1') as { error: string }).error, /user name or password/);
});
