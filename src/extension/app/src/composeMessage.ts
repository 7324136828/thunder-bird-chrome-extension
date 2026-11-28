import type { FullMessage, RichSignature, SendUpload } from './api';

export const ORIGINAL_MAIL_MARKER = '{{[[<<<original mail>>>]]}}';
export const SIGNATURE_MARKER = '{{[[<<<placed signature>>>]]}}';
export const MAX_COMPOSE_FILES = 20;
export const MAX_COMPOSE_FILE_BYTES = 10 * 1024 * 1024;
export const MAX_COMPOSE_TOTAL_BYTES = 20 * 1024 * 1024;

export function plainToEditorHtml(text: string): string {
  const container = document.createElement('div');
  container.textContent = text;
  return container.innerHTML.replace(/\r\n?|\n/g, '<br>');
}

const blocks = new Set(['DIV', 'P', 'BLOCKQUOTE', 'UL', 'OL', 'LI', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'TR']);
const allowed = new Set(['B', 'STRONG', 'I', 'EM', 'U', 'S', 'P', 'DIV', 'BR', 'UL', 'OL', 'LI', 'A', 'BLOCKQUOTE', 'SPAN']);
const discard = new Set(['SCRIPT', 'STYLE', 'TEMPLATE', 'HEAD', 'IFRAME', 'OBJECT', 'EMBED', 'SVG', 'MATH', 'FORM', 'INPUT', 'BUTTON', 'SELECT', 'TEXTAREA', 'VIDEO', 'AUDIO']);

export function safeComposeLink(value: string): string | null {
  if (/[\u0000-\u001f\u007f]/.test(value)) return null;
  try {
    const url = new URL(value);
    if (url.username || url.password) return null;
    if (url.protocol === 'http:' || url.protocol === 'https:') return url.href;
    if (url.protocol === 'mailto:' && url.pathname) return url.href;
  } catch { /* Links must have an explicit supported scheme. */ }
  return null;
}

function plainText(root: Node, imageLabel = true): string {
  function read(node: Node): string {
    if (node.nodeType === Node.TEXT_NODE) return (node.textContent ?? '').replace(/\u00a0/g, ' ');
    if (!(node instanceof Element)) return Array.from(node.childNodes, read).join('');
    if (discard.has(node.tagName)) return '';
    if (node.tagName === 'BR') return '\n';
    if (node.tagName === 'IMG') return imageLabel ? `[Image: ${node.getAttribute('alt') || 'attached image'}]` : '';
    const children = Array.from(node.childNodes, read).join('');
    if (node.tagName === 'LI') {
      const parent = node.parentElement;
      const prefix = parent?.tagName === 'OL' ? `${Array.from(parent.children).indexOf(node) + 1}. ` : '- ';
      return `\n${prefix}${children.trim()}\n`;
    }
    return blocks.has(node.tagName) ? `\n${children}\n` : children;
  }
  return read(root).replace(/\r\n?/g, '\n').replace(/\n{3,}/g, '\n\n').replace(/^\n+|\n+$/g, '');
}

export function originalMailText(original: FullMessage): string {
  if (original.text_body.trim()) return original.text_body.replace(/\r\n?/g, '\n');
  // A template is inert: image sources and styles from the original never enter the editor.
  const template = document.createElement('template');
  template.innerHTML = original.html_body;
  template.content.querySelectorAll('a[href]').forEach((anchor) => {
    const href = safeComposeLink(anchor.getAttribute('href') ?? '');
    const label = anchor.textContent?.trim() ?? '';
    if (href && href !== label) anchor.append(document.createTextNode(` (${href})`));
  });
  return plainText(template.content);
}

function cleanEditorHtml(html: string, uploads: SendUpload[], storedCids = false): { root: HTMLDivElement; inlineIds: Set<string> } {
  const template = document.createElement('template');
  template.innerHTML = html;
  const inertDocument = template.content.ownerDocument;
  const root = inertDocument.createElement('div');
  const images = new Map(uploads.filter((item) => item.inline && item.contentId).map((item) => [item.contentId!, item]));
  const inlineIds = new Set<string>();
  function append(node: Node, parent: Node) {
    if (node.nodeType === Node.TEXT_NODE) {
      parent.appendChild(inertDocument.createTextNode(node.textContent ?? ''));
      return;
    }
    if (!(node instanceof Element) || discard.has(node.tagName)) return;
    if (node.tagName === 'IMG') {
      const source = node.getAttribute('src') ?? '';
      const id = node.getAttribute('data-compose-cid') ?? (storedCids && source.startsWith('cid:') ? source.slice(4) : '');
      const upload = images.get(id);
      if (!upload) return;
      const image = inertDocument.createElement('img');
      image.src = `cid:${id}`;
      image.alt = upload.file.name;
      image.style.maxWidth = '100%';
      parent.appendChild(image);
      inlineIds.add(id);
      return;
    }
    const clean = allowed.has(node.tagName) ? inertDocument.createElement(node.tagName.toLowerCase()) : null;
    if (clean && node.tagName === 'A') {
      const href = safeComposeLink(node.getAttribute('href') ?? '');
      if (href) clean.setAttribute('href', href);
    }
    Array.from(node.childNodes).forEach((child) => append(child, clean ?? parent));
    if (clean) parent.appendChild(clean);
  }
  Array.from(template.content.childNodes).forEach((node) => append(node, root));
  return { root, inlineIds };
}

// Stored signatures use CID references, never remote image URLs or embedded data URLs.
// Restore the editor attribute only for images backed by known, validated local files.
export function buildSignature(html: string, uploads: SendUpload[]): { html: string; uploads: SendUpload[] } {
  const { root, inlineIds } = cleanEditorHtml(html, uploads, true);
  root.querySelectorAll('img').forEach((image) => image.setAttribute('data-compose-cid', (image.getAttribute('src') ?? '').slice(4)));
  const seen = new Set<string>();
  return {
    html: root.textContent?.trim() || root.querySelector('img') ? root.innerHTML : '',
    uploads: uploads.filter((item) => {
      const id = item.contentId;
      if (!item.inline || !id || !inlineIds.has(id) || seen.has(id)) return false;
      seen.add(id);
      return true;
    }),
  };
}

export function signatureEditorHtml(html: string, uploads: SendUpload[]): string {
  return buildSignature(html, uploads).html;
}

export function hasSignature(signature: RichSignature): boolean {
  const { root } = cleanEditorHtml(signature.html, signature.uploads, true);
  return Boolean(root.textContent?.trim() || root.querySelector('img'));
}

export function validateComposeUploads(uploads: SendUpload[]): void {
  if (uploads.length > MAX_COMPOSE_FILES) throw new Error('Attach up to 20 files, including inline images and signature images.');
  if (uploads.some((upload) => upload.file.size > MAX_COMPOSE_FILE_BYTES)) throw new Error('Each file must be no larger than 10 MB.');
  if (uploads.reduce((sum, upload) => sum + upload.file.size, 0) > MAX_COMPOSE_TOTAL_BYTES) throw new Error('The combined files, inline images, and signature images must be no larger than 20 MB.');
}

interface MarkerReplacement {
  marker: string;
  text: string;
  html: (document: Document) => DocumentFragment;
}

function markerMatches(contents: string, replacements: MarkerReplacement[]): { at: number; replacement: MarkerReplacement }[] {
  const matches: { at: number; replacement: MarkerReplacement }[] = [];
  for (const replacement of replacements) {
    for (let at = contents.indexOf(replacement.marker); at >= 0; at = contents.indexOf(replacement.marker, at + replacement.marker.length)) {
      matches.push({ at, replacement });
    }
  }
  return matches.sort((left, right) => left.at - right.at);
}

function replaceTextMarkers(text: string, replacements: MarkerReplacement[]): string {
  let result = '';
  let cursor = 0;
  // Discover every placeholder before expanding any of them, so replacement text stays literal.
  for (const { at, replacement } of markerMatches(text, replacements)) {
    result += text.slice(cursor, at) + replacement.text;
    cursor = at + replacement.marker.length;
  }
  return result + text.slice(cursor);
}

// Record text positions across inline formatting, but never join a marker across separate lines.
function replaceHtmlMarkers(root: HTMLDivElement, replacements: MarkerReplacement[], limit = Infinity): void {
  const positions: ({ node: Text; offset: number } | null)[] = [];
  let contents = '';
  function barrier() { contents += '\n'; positions.push(null); }
  function scan(node: Node) {
    if (node.nodeType === Node.TEXT_NODE) {
      const text = node.textContent ?? '';
      for (let i = 0; i < text.length; i++) {
        contents += text[i];
        positions.push({ node: node as Text, offset: i });
      }
      return;
    }
    if (node instanceof Element && (blocks.has(node.tagName) || node.tagName === 'BR')) barrier();
    Array.from(node.childNodes).forEach(scan);
    if (node instanceof Element && blocks.has(node.tagName)) barrier();
  }
  Array.from(root.childNodes).forEach(scan);
  for (const { at, replacement } of markerMatches(contents, replacements).slice(0, limit).reverse()) {
    const start = positions[at];
    const end = positions[at + replacement.marker.length - 1];
    if (!start || !end) continue;
    const range = root.ownerDocument.createRange();
    range.setStart(start.node, start.offset);
    range.setEnd(end.node, end.offset + 1);
    range.deleteContents();
    range.insertNode(replacement.html(root.ownerDocument));
  }
}

export function placeSignatureMarker(html: string): string {
  const template = document.createElement('template');
  template.innerHTML = html;
  const root = template.content.ownerDocument.createElement('div');
  root.append(template.content);
  const text = plainText(root);
  if (text.includes(SIGNATURE_MARKER)) return html;
  if (text.includes(ORIGINAL_MAIL_MARKER)) {
    replaceHtmlMarkers(root, [{
      marker: ORIGINAL_MAIL_MARKER,
      text: '',
      html: (document) => {
        const fragment = document.createDocumentFragment();
        fragment.append(document.createTextNode(SIGNATURE_MARKER), document.createElement('br'), document.createElement('br'), document.createTextNode(ORIGINAL_MAIL_MARKER));
        return fragment;
      },
    }], 1);
  } else root.append(root.ownerDocument.createElement('br'), root.ownerDocument.createElement('br'), root.ownerDocument.createTextNode(SIGNATURE_MARKER));
  return root.innerHTML;
}

export function buildComposeMessage(html: string, original: FullMessage | null | undefined, uploads: SendUpload[], signature: RichSignature | string = ''): { text: string; html: string; uploads: SendUpload[] } {
  const { root, inlineIds } = cleanEditorHtml(html, uploads);
  let text = plainText(root);
  if (text.includes(ORIGINAL_MAIL_MARKER) && !original) throw new Error('The original-mail placeholder needs a reply or forward. Remove it before sending a new message.');
  const usesSignature = text.includes(SIGNATURE_MARKER);
  const legacySignature = typeof signature === 'string';
  const signatureRoot = legacySignature ? null : cleanEditorHtml(signature.html, signature.uploads, true);
  const signatureText = legacySignature ? (signature.trim() ? signature.replace(/\r\n?/g, '\n') : '') : plainText(signatureRoot!.root);
  const signatureUploads: SendUpload[] = [];
  if (usesSignature && signatureRoot && !legacySignature) {
    const usedIds = new Set(uploads.map((item) => item.contentId).filter(Boolean));
    const replacements = new Map<string, string>();
    let index = 0;
    for (const item of signature.uploads) {
      const id = item.contentId;
      if (!item.inline || !id || !signatureRoot.inlineIds.has(id) || replacements.has(id)) continue;
      let replacement: string;
      do { replacement = `signature-${++index}@inline.local`; } while (usedIds.has(replacement));
      usedIds.add(replacement);
      replacements.set(id, replacement);
      signatureUploads.push({ ...item, contentId: replacement });
    }
    signatureRoot.root.querySelectorAll('img').forEach((image) => {
      const id = (image.getAttribute('src') ?? '').slice(4);
      image.setAttribute('src', `cid:${replacements.get(id)}`);
    });
  }
  const replacements: MarkerReplacement[] = [{
    marker: SIGNATURE_MARKER,
    text: signatureText,
    html: (document) => {
      const fragment = document.createDocumentFragment();
      if (signatureRoot) Array.from(signatureRoot.root.childNodes).forEach((node) => fragment.append(document.importNode(node, true)));
      else if (signatureText) fragment.append(document.createTextNode(signatureText));
      return fragment;
    },
  }];
  if (original) {
    const intro = `On ${original.date ?? ''}, ${original.from_addr} wrote:`;
    const quote = originalMailText(original);
    const quoted = quote.split('\n').map((line) => `> ${line}`).join('\n');
    replacements.push({
      marker: ORIGINAL_MAIL_MARKER,
      text: `${intro}\n${quoted}`,
      html: (document) => {
        const fragment = document.createDocumentFragment();
        const heading = document.createElement('div');
        heading.textContent = intro;
        const blockquote = document.createElement('blockquote');
        blockquote.style.whiteSpace = 'pre-wrap';
        blockquote.textContent = quote;
        fragment.append(heading, blockquote);
        return fragment;
      },
    });
  }
  text = replaceTextMarkers(text, replacements);
  replaceHtmlMarkers(root, replacements);
  return {
    text,
    html: `<div style="white-space:pre-wrap">${root.innerHTML}</div>`,
    uploads: [...uploads.filter((item) => !item.inline || (item.contentId && inlineIds.has(item.contentId))), ...signatureUploads],
  };
}

export async function localRasterImage(file: File): Promise<{ file: File; url: string }> {
  const bytes = new Uint8Array(await file.slice(0, 32).arrayBuffer());
  const starts = (...values: number[]) => values.every((value, index) => bytes[index] === value);
  const ascii = (start: number, end: number) => String.fromCharCode(...bytes.slice(start, end));
  let type = '';
  if (starts(137, 80, 78, 71, 13, 10, 26, 10)) type = 'image/png';
  else if (starts(255, 216, 255)) type = 'image/jpeg';
  else if (['GIF87a', 'GIF89a'].includes(ascii(0, 6))) type = 'image/gif';
  else if (ascii(0, 4) === 'RIFF' && ascii(8, 12) === 'WEBP') type = 'image/webp';
  else if (ascii(0, 2) === 'BM') type = 'image/bmp';
  if (!type) throw new Error(`${file.name}: choose a PNG, JPEG, GIF, WebP, or BMP image.`);
  const normalized = file.type === type ? file : new File([file], file.name, { type, lastModified: file.lastModified });
  const url = URL.createObjectURL(normalized);
  try {
    const image = new Image();
    image.src = url;
    await image.decode();
    if (!image.naturalWidth || !image.naturalHeight || image.naturalWidth * image.naturalHeight > 25_000_000) throw new Error('Image dimensions are too large.');
    return { file: normalized, url };
  } catch {
    URL.revokeObjectURL(url);
    throw new Error(`${file.name}: this image could not be opened safely.`);
  }
}
