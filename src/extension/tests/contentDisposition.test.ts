import assert from 'node:assert/strict';
import { test } from 'node:test';
import { filenameFromContentDisposition, filenameFromUrl } from '../app/src/platform/contentDisposition.ts';

test('plain quoted file names (backend .eml / attachment responses)', () => {
  assert.equal(filenameFromContentDisposition('attachment; filename="message-42.eml"'), 'message-42.eml');
  assert.equal(filenameFromContentDisposition('attachment; filename=report.csv'), 'report.csv');
  assert.equal(filenameFromContentDisposition('attachment; filename="a \\"quoted\\" name.txt"'), 'a "quoted" name.txt');
});

test('RFC 5987 filename* wins and is percent-decoded (doctor ZIP responses)', () => {
  assert.equal(
    filenameFromContentDisposition("attachment; filename*=utf-8''inbox%20export_audit.zip"),
    'inbox export_audit.zip',
  );
  assert.equal(
    filenameFromContentDisposition("attachment; filename=\"fallback.zip\"; filename*=UTF-8''%C3%BCber.zip"),
    'über.zip',
  );
  assert.equal(filenameFromContentDisposition("attachment; filename*=iso-8859-1''%FCber.txt"), 'über.txt');
  assert.equal(filenameFromContentDisposition("attachment; filename*=utf-8''bad%E0%A4%A.txt"), 'bad%E0%A4%A.txt');
});

test('missing header or name', () => {
  assert.equal(filenameFromContentDisposition(null), '');
  assert.equal(filenameFromContentDisposition('inline'), '');
});

test('file name from URL path', () => {
  assert.equal(filenameFromUrl('http://127.0.0.1:48101/api/jobs/abc/files/report/senders.csv'), 'senders.csv');
  assert.equal(filenameFromUrl('/api/jobs/abc/files/report%20one.md?x=1'), 'report one.md');
  assert.equal(filenameFromUrl('http://127.0.0.1:48101/'), '');
});
