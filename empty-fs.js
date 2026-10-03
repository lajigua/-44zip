'use strict';
// Browser shim for node:fs — the web build never touches the file system.
// Only module-level requires must resolve; fs-using code paths are not invoked.
module.exports = {};
