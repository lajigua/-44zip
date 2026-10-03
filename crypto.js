'use strict';
// Browser shim for the node:crypto APIs used by the KFB tool:
// createHash('sha256'), createDecipheriv('aes-256-ctr'), createCipheriv('aes-256-ctr')
const aesjs = require('aes-js');
const { sha256: sha256hex } = require('js-sha256');

function toBytes(data) {
  if (Buffer.isBuffer(data)) return new Uint8Array(data);
  if (data instanceof Uint8Array) return data;
  if (typeof data === 'string') return new Uint8Array(Buffer.from(data, 'utf8'));
  return new Uint8Array(data);
}

function createHash(algorithm) {
  if (algorithm !== 'sha256') throw new Error(`unsupported hash algorithm: ${algorithm}`);
  const chunks = [];
  return {
    update(data) { chunks.push(toBytes(data)); return this; },
    digest(encoding) {
      const total = chunks.reduce((n, c) => n + c.length, 0);
      const merged = new Uint8Array(total);
      let pos = 0;
      for (const c of chunks) { merged.set(c, pos); pos += c.length; }
      const hex = sha256hex(merged);
      return encoding === 'hex' ? hex : Buffer.from(hex, 'hex');
    },
  };
}

function incrementCounter(counter) {
  for (let i = counter.length - 1; i >= 0; i--) {
    counter[i] = (counter[i] + 1) & 0xff;
    if (counter[i] !== 0) break;
  }
}

function aesCtrProcess(key, iv, data) {
  const aes = new aesjs.AES(toBytes(key));
  const counter = new Uint8Array(16);
  counter.set(toBytes(iv).subarray(0, 16));
  const input = toBytes(data);
  const output = new Uint8Array(input.length);
  let keystream = new Uint8Array(16);
  let blockPos = 16;
  for (let i = 0; i < input.length; i++) {
    if (blockPos === 16) {
      keystream = aes.encrypt(counter); // aes-js returns the encrypted block
      incrementCounter(counter);
      blockPos = 0;
    }
    output[i] = input[i] ^ keystream[blockPos];
    blockPos++;
  }
  return Buffer.from(output);
}

function assertAes256Ctr(algorithm) {
  if (algorithm !== 'aes-256-ctr') throw new Error(`unsupported cipher algorithm: ${algorithm}`);
}

function createDecipheriv(algorithm, key, iv) {
  assertAes256Ctr(algorithm);
  return {
    update(data) { return aesCtrProcess(key, iv, data); },
    final() { return Buffer.alloc(0); },
  };
}

function createCipheriv(algorithm, key, iv) {
  assertAes256Ctr(algorithm);
  return {
    update(data) { return aesCtrProcess(key, iv, data); },
    final() { return Buffer.alloc(0); },
  };
}

module.exports = { createHash, createDecipheriv, createCipheriv };
