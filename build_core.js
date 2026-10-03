'use strict';
// esbuild config: bundle web_core.js for the browser (also runnable in node for testing)
const path = require('path');
const esbuild = require('esbuild');

esbuild.build({
  entryPoints: [path.join(__dirname, 'web_core.js')],
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: ['es2020'],
  minify: true,
  outfile: path.join(__dirname, 'dist', 'kfb_core.bundle.js'),
  alias: {
    'node:fs': path.join(__dirname, 'shims', 'empty-fs.js'),
    fs: path.join(__dirname, 'shims', 'empty-fs.js'),
    'node:path': path.join(__dirname, 'shims', 'empty-path.js'),
    path: path.join(__dirname, 'shims', 'empty-path.js'),
    'node:crypto': path.join(__dirname, 'shims', 'crypto.js'),
    crypto: path.join(__dirname, 'shims', 'crypto.js'),
  },
  define: { 'process.env.NODE_ENV': '"production"' },
  logLevel: 'info',
}).then(() => console.log('core bundle OK')).catch((e) => { console.error(e); process.exit(1); });
