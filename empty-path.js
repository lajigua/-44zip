'use strict';
// Browser shim for node:path — minimal in-memory implementations.
function normalizePath(p) { return String(p); }
module.exports = {
  resolve: (...parts) => (parts.length ? parts[parts.length - 1] : '.'),
  join: (...parts) => parts.filter(Boolean).join('/'),
  basename: (p) => String(p).split('/').pop(),
  dirname: (p) => {
    const idx = String(p).lastIndexOf('/');
    return idx < 0 ? '.' : String(p).slice(0, idx);
  },
  extname: (p) => {
    const base = String(p).split('/').pop();
    const idx = base.lastIndexOf('.');
    return idx < 0 ? '' : base.slice(idx);
  },
};
