import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * One Vite project builds every extension page:
 *   index.html    the three-pane webmail app (opened in a tab by the action)
 *   options.html  backend URL settings (options_ui)
 *   background.js the MV3 service worker (fixed name, referenced by manifest)
 * Files in public/ (the sandboxed frame host) are copied verbatim.
 *
 * `npm run dev` keeps the original dev-server workflow: the app is served on
 * port 3741 and relative /api calls are proxied to the local Rust backend.
 */
const root = fileURLToPath(new URL('.', import.meta.url));
const backendUrl = process.env.VITE_BACKEND_URL || 'http://127.0.0.1:48101';
const devPort = 3741;
const devOrigins = new Set([`http://127.0.0.1:${devPort}`, `http://localhost:${devPort}`, `http://[::1]:${devPort}`]);

export default defineConfig({
  root,
  base: './',
  plugins: [react()],
  server: {
    // Loopback by default: the proxy forwards to a backend holding unlocked
    // mail sessions, so it must not be reachable from the network.
    host: process.env.FRONTEND_HOST || '127.0.0.1',
    port: devPort,
    strictPort: true,
    proxy: {
      '/api': {
        target: backendUrl,
        changeOrigin: true,
        // The backend refuses every web Origin (only extension origins and
        // Origin-less local tools are allowed), so POST/PUT/DELETE from this
        // dev page would get 403. Drop the Origin only when it is this dev
        // server itself; any other page's Origin is forwarded and refused.
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyReq, req) => {
            const origin = req.headers.origin;
            if (origin && devOrigins.has(origin.toLowerCase())) proxyReq.removeHeader('origin');
          });
        },
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'chrome116',
    modulePreload: { polyfill: false },
    rollupOptions: {
      input: {
        index: `${root}index.html`,
        options: `${root}options.html`,
        background: `${root}src/background/serviceWorker.ts`,
      },
      output: {
        entryFileNames: (chunk) => (chunk.name === 'background' ? 'background.js' : 'assets/[name]-[hash].js'),
      },
    },
  },
});
