import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  defaultIncomingPort,
  isPop3Account,
  normalizeMailProtocol,
  POP3_IMAP_ONLY_DETAIL,
  portAfterProtocolChange,
} from '../app/src/platform/mailProtocol.ts';

test('protocol normalization: only an explicit pop3 is POP3', () => {
  assert.equal(normalizeMailProtocol('pop3'), 'pop3');
  assert.equal(normalizeMailProtocol(' POP3 '), 'pop3');
  for (const value of ['imap', 'IMAP', '', undefined, null, 'smtp']) assert.equal(normalizeMailProtocol(value), 'imap');
  assert.equal(isPop3Account({ incoming_mail_protocol: 'pop3' }), true);
  assert.equal(isPop3Account({ incoming_mail_protocol: 'imap' }), false);
  assert.equal(isPop3Account({}), false);
  assert.equal(isPop3Account(undefined), false);
});

test('default incoming ports: 993/143 IMAP, 995/110 POP3', () => {
  assert.equal(defaultIncomingPort('imap', 'SSL/TLS'), 993);
  assert.equal(defaultIncomingPort('imap', 'STARTTLS'), 143);
  assert.equal(defaultIncomingPort('imap', 'NONE'), 143);
  assert.equal(defaultIncomingPort('pop3', 'SSL/TLS'), 995);
  assert.equal(defaultIncomingPort('pop3', 'ssl'), 995);
  assert.equal(defaultIncomingPort('pop3', 'STARTTLS'), 110);
  assert.equal(defaultIncomingPort('pop3', 'NONE'), 110);
  assert.equal(defaultIncomingPort('', 'SSL/TLS'), 993);
});

test('switching protocol follows default ports but keeps typed ports', () => {
  assert.equal(portAfterProtocolChange(993, 'imap', 'pop3'), 995);
  assert.equal(portAfterProtocolChange(143, '', 'pop3'), 110);
  assert.equal(portAfterProtocolChange(995, 'pop3', 'imap'), 993);
  assert.equal(portAfterProtocolChange(110, 'pop3', 'imap'), 143);
  assert.equal(portAfterProtocolChange(1993, 'imap', 'pop3'), 1993);
});

test('IMAP-only detail matches mail-core pop3::IMAP_ONLY_MESSAGE', async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const pop3 = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'mail-core', 'src', 'pop3.rs');
  if (!fs.existsSync(pop3)) return; // extension checked out on its own
  assert.ok(fs.readFileSync(pop3, 'utf8').includes(`"${POP3_IMAP_ONLY_DETAIL}"`));
});
