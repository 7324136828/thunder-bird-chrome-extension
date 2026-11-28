#!/usr/bin/env node
/**
 * Generate the extension icons (icons/icon-16.png, -48, -128) without any
 * image library: a rounded blue badge with a white envelope and the app's
 * green accent. Each pixel is 4x4 supersampled for smooth edges.
 *
 *   node tools/gen-icons.mjs [outDir]     (default: icons/ next to tools/)
 */
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const ICON_SIZES = [16, 48, 128];
const SUBSAMPLES = 4;

// ------------------------------------------------------------------ PNG

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([length, body, crc]);
}

/** Encode RGBA bytes (size*size*4) as a PNG. */
function encodePng(size, rgba) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8; // bit depth
  header[9] = 6; // RGBA
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y += 1) {
    raw[y * (size * 4 + 1)] = 0; // filter: none
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

// ------------------------------------------------------------------ shapes
// All geometry is in a 0..1 unit square.

function insideRoundedRect(x, y, x0, y0, x1, y1, radius) {
  if (x < x0 || x > x1 || y < y0 || y > y1) return false;
  const cx = Math.min(Math.max(x, x0 + radius), x1 - radius);
  const cy = Math.min(Math.max(y, y0 + radius), y1 - radius);
  return (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2;
}

function distanceToSegment(x, y, ax, ay, bx, by) {
  const dx = bx - ax;
  const dy = by - ay;
  const t = Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(x - (ax + t * dx), y - (ay + t * dy));
}

const BLUE_TOP = [47, 125, 225];
const BLUE_BOTTOM = [22, 72, 150];
const WHITE = [255, 255, 255];
const FLAP = [30, 92, 180];
const GREEN = [94, 234, 153];

/** Colour [r, g, b, a] of the icon at unit coordinates (x, y). */
function sample(x, y, size) {
  // Small icons get a thicker envelope stroke so they stay legible.
  const stroke = size <= 16 ? 0.085 : 0.05;
  if (!insideRoundedRect(x, y, 0.02, 0.02, 0.98, 0.98, 0.2)) return [0, 0, 0, 0];

  // Notification dot (top right) over everything else.
  if ((x - 0.78) ** 2 + (y - 0.24) ** 2 <= 0.13 ** 2) {
    if ((x - 0.78) ** 2 + (y - 0.24) ** 2 >= 0.1 ** 2) return [...BLUE_BOTTOM, 255];
    return [...GREEN, 255];
  }

  const ex0 = 0.18;
  const ex1 = 0.82;
  const ey0 = 0.32;
  const ey1 = 0.74;
  if (insideRoundedRect(x, y, ex0, ey0, ex1, ey1, 0.05)) {
    const flap = Math.min(
      distanceToSegment(x, y, ex0 + 0.02, ey0 + 0.03, 0.5, 0.55),
      distanceToSegment(x, y, ex1 - 0.02, ey0 + 0.03, 0.5, 0.55),
    );
    return flap <= stroke / 2 ? [...FLAP, 255] : [...WHITE, 255];
  }

  const t = y;
  return [
    ...BLUE_TOP.map((top, index) => Math.round(top + (BLUE_BOTTOM[index] - top) * t)),
    255,
  ];
}

export function renderIcon(size) {
  const rgba = Buffer.alloc(size * size * 4);
  for (let py = 0; py < size; py += 1) {
    for (let px = 0; px < size; px += 1) {
      let r = 0;
      let g = 0;
      let b = 0;
      let a = 0;
      for (let sy = 0; sy < SUBSAMPLES; sy += 1) {
        for (let sx = 0; sx < SUBSAMPLES; sx += 1) {
          const [cr, cg, cb, ca] = sample((px + (sx + 0.5) / SUBSAMPLES) / size, (py + (sy + 0.5) / SUBSAMPLES) / size, size);
          r += cr * ca;
          g += cg * ca;
          b += cb * ca;
          a += ca;
        }
      }
      const offset = (py * size + px) * 4;
      rgba[offset] = a ? Math.round(r / a) : 0;
      rgba[offset + 1] = a ? Math.round(g / a) : 0;
      rgba[offset + 2] = a ? Math.round(b / a) : 0;
      rgba[offset + 3] = Math.round(a / (SUBSAMPLES * SUBSAMPLES));
    }
  }
  return encodePng(size, rgba);
}

export function writeIcons(outDir = path.join(ROOT, 'icons')) {
  fs.mkdirSync(outDir, { recursive: true });
  return ICON_SIZES.map((size) => {
    const file = path.join(outDir, `icon-${size}.png`);
    fs.writeFileSync(file, renderIcon(size));
    return file;
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const outDir = process.argv[2] ? path.resolve(process.argv[2]) : undefined;
  for (const file of writeIcons(outDir)) console.log(`wrote ${path.relative(process.cwd(), file)}`);
}
