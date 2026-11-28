import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseMailto } from '../app/src/mailto.ts';
import { isMailtoCandidate, MAX_MAILTO_LENGTH } from '../app/src/background/messages.ts';

// The context menu hands raw links to the app, which parses them with the
// original mailto.ts. These cases pin the behaviour the extension relies on.

test('parses recipients, subject and body', () => {
  assert.deepEqual(parseMailto('mailto:alice@example.com?cc=bob@example.com&subject=Hello%20there&body=Line1%0D%0ALine2'), {
    to: 'alice@example.com',
    cc: 'bob@example.com',
    bcc: '',
    subject: 'Hello there',
    body: 'Line1\nLine2',
  });
});

test('literal plus stays a plus and repeated recipients are joined', () => {
  const draft = parseMailto('mailto:a+tag@example.com?to=b@example.com&subject=1+1&to=c@example.com');
  assert.ok(draft);
  assert.equal(draft.to, 'a+tag@example.com, b@example.com, c@example.com');
  assert.equal(draft.subject, '1+1');
});

test('rejects header injection and non-mailto links', () => {
  assert.equal(parseMailto('mailto:a@example.com?subject=Hi%0D%0ABcc:evil@example.com'), null);
  assert.equal(parseMailto('https://example.com'), null);
  assert.equal(parseMailto(`mailto:a@example.com?body=${'x'.repeat(9000)}`), null);
});

test('service worker pre-check matches the parser limits', () => {
  assert.equal(MAX_MAILTO_LENGTH, 8192);
  assert.equal(isMailtoCandidate('mailto:a@example.com'), true);
  assert.equal(isMailtoCandidate('MAILTO:a@example.com'), true);
  assert.equal(isMailtoCandidate('https://example.com'), false);
  assert.equal(isMailtoCandidate(`mailto:${'a'.repeat(8200)}`), false);
  assert.equal(isMailtoCandidate(undefined), false);
});
