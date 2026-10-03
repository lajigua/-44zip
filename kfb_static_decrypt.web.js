#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const kfbDecoder = require('./kfb_schema_decoder.js');
let lzmaWorker = null;
try {
  lzmaWorker = require('./vendor_lzma.js').LZMA_WORKER;
} catch (_) {
  // vendor_lzma.js 缺失时仅影响 --match-size 的 LZMA 候选与 LZMA 块读取
}
const readableAdapter = require('./kfb_readable_adapter.js');

const MAX_DECOMPRESSED_BYTES = 1024 * 1024 * 1024;
const WIRE_NAMES = [
  'Variant',
  'Fixed32',
  'Fixed64',
  'Object',
  'String',
  'List',
  'Dictionary',
  'Packed',
];

function usage(exitCode = 0) {
  const stream = exitCode === 0 ? process.stdout : process.stderr;
  stream.write(`KFB static decrypt / wire inspector

Usage:
  node kfb_static_decrypt.js decrypt <encrypted> <output.kfb> --key <64-hex> [--wire-json <output.json>]
  node kfb_static_decrypt.js decrypt <encrypted> <output.kfb> --key-db <ninja_aes_keys.json> --ninja-id <id> [--theme-id 0]
  node kfb_static_decrypt.js decrypt <encrypted> <output.kfb> --key-db <ninja_aes_keys.json> --res-name <name>
  node kfb_static_decrypt.js decrypt-bundle <bundle> <textasset-name|auto> <output> --key <64-hex>
  node kfb_static_decrypt.js decode-bundle <bundle> <textasset-name|auto> <output-base> --key <64-hex> [--schema <kfb_schema.json>] [--dump-layout <kfb_dump_layout.json>]
  node kfb_static_decrypt.js decode <plain.kfb> <output-base> [--schema <kfb_schema.json>] [--dump-layout <kfb_dump_layout.json>]
  node kfb_static_decrypt.js encode <readable.json|readable.xml|semantic.json> <output.kfb> [--schema <kfb_schema.json>] [--dump-layout <kfb_dump_layout.json>]
  node kfb_static_decrypt.js encode-bundle <bundle> <textasset-name|auto> <readable.json|readable.xml|semantic.json> <output.bundle> --key <64-hex> [--schema <kfb_schema.json>] [--dump-layout <kfb_dump_layout.json>] [--crc <hex|decimal>] [--unityfs] [--match-size]
    --match-size: LZ4HC 重压缩内层容器和 UnityFS 数据块，并把输出补零对齐到与原包完全一致的字节数（默认跳过 CRC 修复；放不下时自动退回裸 UnityFS 壳）
  node kfb_static_decrypt.js build-layout <dump.cs> <kfb_dump_layout.json> [--schema <kfb_schema.json>]
  node kfb_static_decrypt.js crc-info <bundle> [--crc <hex|decimal>]
  node kfb_static_decrypt.js inspect <plain.kfb> <output.json> [--max-depth 2]
  node kfb_static_decrypt.js self-test <plain.kfb>
  node kfb_static_decrypt.js decoder-self-test

Container:
  [4-byte outer header][16-byte IV][AES-256-CTR ciphertext]
  AES plaintext is an LZ4 block with a 4-byte little-endian output-size prefix.
`);
  process.exit(exitCode);
}

function fail(message) {
  throw new Error(message);
}

function parseArguments(argv) {
  const positional = [];
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (!value.startsWith('--')) {
      positional.push(value);
      continue;
    }
    const name = value.slice(2);
    if (name === 'help' || name === 'unityfs' || name === 'match-size') {
      options[name] = true;
      continue;
    }
    if (index + 1 >= argv.length || argv[index + 1].startsWith('--')) {
      fail(`missing value for --${name}`);
    }
    options[name] = argv[index + 1];
    index += 1;
  }
  return { positional, options };
}

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1) !== 0 ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1);
    }
    table[index] = value >>> 0;
  }
  return table;
})();

function crc32(data) {
  let value = 0xffffffff;
  for (const byte of data) value = (CRC32_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8)) >>> 0;
  return (value ^ 0xffffffff) >>> 0;
}

function crc32Hex(value) { return `0x${(value >>> 0).toString(16).padStart(8, '0').toUpperCase()}`; }

function parseCrc32(value) {
  const text = String(value || '').trim();
  let parsed;
  if (/^0x[0-9a-f]{1,8}$/i.test(text)) parsed = BigInt(text);
  else if (/^\d+$/.test(text)) parsed = BigInt(text);
  else fail(`invalid CRC32 value: ${value}`);
  if (parsed < 0n || parsed > 0xffffffffn) fail(`CRC32 is outside uint32: ${value}`);
  return Number(parsed) >>> 0;
}

function crc32AppendFix(data, targetCrc) {
  const zeroPatch = Buffer.alloc(4);
  const current = crc32(Buffer.concat([data, zeroPatch]));
  const delta = (targetCrc ^ current) >>> 0;
  const zeroPatchCrc = crc32(zeroPatch);
  const matrix = Array(32).fill(0n);
  const rhs = Array(32).fill(0);
  for (let column = 0; column < 32; column += 1) {
    const test = Buffer.alloc(4);
    test[Math.floor(column / 8)] = 1 << (column % 8);
    const effect = (crc32(test) ^ zeroPatchCrc) >>> 0;
    for (let row = 0; row < 32; row += 1) {
      if (((effect >>> row) & 1) !== 0) matrix[row] |= 1n << BigInt(column);
    }
  }
  for (let row = 0; row < 32; row += 1) rhs[row] = (delta >>> row) & 1;
  for (let column = 0; column < 32; column += 1) {
    let pivot = column;
    const mask = 1n << BigInt(column);
    while (pivot < 32 && (matrix[pivot] & mask) === 0n) pivot += 1;
    if (pivot === 32) fail('CRC32 fix matrix is singular');
    [matrix[column], matrix[pivot]] = [matrix[pivot], matrix[column]];
    [rhs[column], rhs[pivot]] = [rhs[pivot], rhs[column]];
    for (let row = 0; row < 32; row += 1) {
      if (row !== column && (matrix[row] & mask) !== 0n) {
        matrix[row] ^= matrix[column];
        rhs[row] ^= rhs[column];
      }
    }
  }
  const fix = Buffer.alloc(4);
  for (let bit = 0; bit < 32; bit += 1) if (rhs[bit] !== 0) fix[Math.floor(bit / 8)] |= 1 << (bit % 8);
  const fixed = Buffer.concat([data, fix]);
  const verified = crc32(fixed);
  if (verified !== (targetCrc >>> 0)) fail(`CRC32 fix verification failed: ${crc32Hex(verified)}`);
  return { data: fixed, fix, before: crc32(data), target: targetCrc >>> 0, after: verified };
}

function resolveBundleCrcTarget(bundlePath, originalCrc, options = {}) {
  if (options.crc !== undefined) return { value: parseCrc32(options.crc), source: 'command_line' };
  const stem = path.basename(bundlePath).split('.')[0];
  if (/^\d+$/.test(stem)) return { value: Number(BigInt(stem) & 0xffffffffn) >>> 0, source: `filename:${stem}` };
  return { value: originalCrc >>> 0, source: 'original_bundle' };
}

function keySummary(key) {
  const hex = key.toString('hex');
  return `${hex.slice(0, 8)}...${hex.slice(-8)}`;
}

function atomicWrite(filePath, data) {
  const absolute = path.resolve(filePath);
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  const temporary = `${absolute}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, data);
  if (fs.existsSync(absolute)) {
    fs.unlinkSync(absolute);
  }
  fs.renameSync(temporary, absolute);
  return absolute;
}

function parseHexKey(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    fail('AES key must be exactly 64 hexadecimal characters');
  }
  return Buffer.from(normalized, 'hex');
}

function normalizeNinjaId(value) {
  const text = String(value || '').trim();
  if (!/^\d+$/.test(text)) {
    fail(`invalid ninja id: ${value}`);
  }
  let number = BigInt(text);
  if (text.length >= 5 && text.length < 8) {
    number = number * 1000n + 1n;
  }
  if (number <= 0n || number > 0xffffffffn) {
    fail(`ninja id is outside uint32: ${value}`);
  }
  return Number(number);
}

function resolveKey(options) {
  if (options.key) {
    return { key: parseHexKey(options.key), source: 'command_line' };
  }
  if (!options['key-db']) {
    fail('provide --key or --key-db');
  }
  const databasePath = path.resolve(options['key-db']);
  const database = JSON.parse(fs.readFileSync(databasePath, 'utf8'));
  let secretKey = '';
  let source = '';
  if (options['ninja-id']) {
    const ninjaId = normalizeNinjaId(options['ninja-id']);
    const themeId = Number(options['theme-id'] || 0);
    const record = Array.isArray(database.ninja_keys)
      ? database.ninja_keys.find((entry) =>
          Number(entry.ninja_id) === ninjaId && Number(entry.theme_id || 0) === themeId)
      : undefined;
    if (!record) {
      fail(`no key for ninja_id=${ninjaId} theme_id=${themeId}`);
    }
    secretKey = record.secret_key;
    source = `ninja:${ninjaId}:${themeId}`;
  } else if (options['res-name']) {
    const record = Array.isArray(database.resource_keys)
      ? database.resource_keys.find((entry) => entry.res_name === options['res-name'])
      : undefined;
    if (!record) {
      fail(`no key for res_name=${options['res-name']}`);
    }
    secretKey = record.secret_key;
    source = `resource:${options['res-name']}`;
  } else {
    fail('--key-db requires --ninja-id or --res-name');
  }
  return { key: parseHexKey(secretKey), source: `${source}@${databasePath}` };
}

function readExtendedLength(input, state, initial) {
  let length = initial;
  if (initial !== 15) {
    return length;
  }
  while (true) {
    if (state.position >= input.length) {
      fail('truncated LZ4 extended length');
    }
    const value = input[state.position];
    state.position += 1;
    length += value;
    if (value !== 255) {
      return length;
    }
  }
}

function decompressLz4Raw(compressed, expectedSize) {
  if (expectedSize === 0 || expectedSize > MAX_DECOMPRESSED_BYTES) {
    fail(`invalid LZ4 output size: ${expectedSize}`);
  }
  const output = Buffer.allocUnsafe(expectedSize);
  const state = { position: 0 };
  let outputPosition = 0;

  while (state.position < compressed.length) {
    const token = compressed[state.position];
    state.position += 1;

    const literalLength = readExtendedLength(compressed, state, token >>> 4);
    if (state.position + literalLength > compressed.length ||
        outputPosition + literalLength > output.length) {
      fail('invalid LZ4 literal length');
    }
    compressed.copy(output, outputPosition, state.position, state.position + literalLength);
    state.position += literalLength;
    outputPosition += literalLength;

    if (state.position === compressed.length) {
      break;
    }
    if (state.position + 2 > compressed.length) {
      fail('truncated LZ4 match offset');
    }
    const matchOffset = compressed.readUInt16LE(state.position);
    state.position += 2;
    if (matchOffset === 0 || matchOffset > outputPosition) {
      fail(`invalid LZ4 match offset: ${matchOffset}`);
    }

    const matchLength = readExtendedLength(compressed, state, token & 0x0f) + 4;
    if (outputPosition + matchLength > output.length) {
      fail('LZ4 match exceeds declared output size');
    }
    for (let index = 0; index < matchLength; index += 1) {
      output[outputPosition] = output[outputPosition - matchOffset];
      outputPosition += 1;
    }
  }

  if (outputPosition !== expectedSize) {
    fail(`LZ4 size mismatch: expected ${expectedSize}, decoded ${outputPosition}`);
  }
  return output;
}

function decompressLz4Stored(input) {
  if (input.length < 5) {
    fail('AES plaintext is too short for an LZ4 stored-size block');
  }
  return decompressLz4Raw(input.subarray(4), input.readUInt32LE(0));
}


// ---------------------------------------------------------------------------
// LZ4 block compressor (output is a standard LZ4 block decodable by
// LZ4_decompress_safe). Level < 9: fast greedy; level >= 9: optimal parsing
// (backward DP with an exact byte-price model), aimed at matching LZ4HC.
// ---------------------------------------------------------------------------
const LZ4_MIN_MATCH = 4;
const LZ4_HASH_LOG = 17;
const LZ4_HASH_SIZE = 1 << LZ4_HASH_LOG;

function lz4Hash4(value) {
  return ((value * 2654435761) >>> 0) >>> (32 - LZ4_HASH_LOG);
}

function lz4CountMatch(buffer, a, b, limit) {
  let count = 0;
  while (b + count + 4 <= limit) {
    const diff = (buffer.readUInt32LE(a + count) ^ buffer.readUInt32LE(b + count)) >>> 0;
    if (diff === 0) { count += 4; continue; }
    return count + ((31 - Math.clz32((diff & -diff) >>> 0)) >> 3);
  }
  while (b + count < limit && buffer[a + count] === buffer[b + count]) count += 1;
  return count;
}

function lz4EmitSequence(out, literals, literalStart, literalLength, offset, matchLength) {
  const ml = matchLength - LZ4_MIN_MATCH;
  const tokenPosition = out.length;
  out.push(0);
  let token = 0;
  if (literalLength >= 15) {
    token |= 0xf0;
    let remaining = literalLength - 15;
    while (remaining >= 255) { out.push(255); remaining -= 255; }
    out.push(remaining);
  } else {
    token |= literalLength << 4;
  }
  for (let index = 0; index < literalLength; index += 1) out.push(literals[literalStart + index]);
  out[tokenPosition] = token;
  if (offset !== 0) {
    out.push(offset & 0xff, (offset >> 8) & 0xff);
    if (ml >= 15) {
      let remaining = ml - 15;
      while (remaining >= 255) { out.push(255); remaining -= 255; }
      out.push(remaining);
    }
    out[tokenPosition] |= Math.min(15, ml);
  }
}

function compressLz4Greedy(input) {
  const size = input.length;
  const out = [];
  if (size === 0) return Buffer.from(out);
  const table = new Int32Array(LZ4_HASH_SIZE).fill(-1);
  const matchLimit = size - 12;
  let anchor = 0;
  let cursor = 0;
  while (cursor <= matchLimit) {
    const hash = lz4Hash4(input.readUInt32LE(cursor));
    const reference = table[hash];
    table[hash] = cursor;
    if (reference >= 0 && cursor - reference <= 65535 &&
        input.readUInt32LE(reference) === input.readUInt32LE(cursor)) {
      let matchLength = LZ4_MIN_MATCH + lz4CountMatch(input, reference + LZ4_MIN_MATCH, cursor + LZ4_MIN_MATCH, size);
      if (cursor + matchLength > size - 5) matchLength = size - 5 - cursor;
      if (matchLength < LZ4_MIN_MATCH) { cursor += 1; continue; }
      lz4EmitSequence(out, input, anchor, cursor - anchor, cursor - reference, matchLength);
      cursor += matchLength;
      anchor = cursor;
      const end = Math.min(cursor, matchLimit + 1);
      for (let p = cursor - 2; p < end; p += 1) {
        if (p >= 0) table[lz4Hash4(input.readUInt32LE(p))] = p;
      }
    } else {
      cursor += 1;
    }
  }
  lz4EmitSequence(out, input, anchor, size - anchor, 0, LZ4_MIN_MATCH);
  return Buffer.from(out);
}

function lz4LengthPrice(length) {
  const code = length - LZ4_MIN_MATCH;
  return code < 15 ? 0 : 1 + Math.floor((code - 15) / 255);
}

function compressLz4Optimal(input, maxDepth = 512, maxCandidates = 6) {
  const size = input.length;
  const out = [];
  if (size === 0) return Buffer.from(out);
  const head = new Int32Array(LZ4_HASH_SIZE).fill(-1);
  const previous = new Int32Array(size).fill(-1);
  const matchLimit = size - 12;
  for (let p = 0; p <= matchLimit; p += 1) {
    const hash = lz4Hash4(input.readUInt32LE(p));
    previous[p] = head[hash];
    head[hash] = p;
  }
  const cost = new Float64Array(size + 1);
  const choice = new Array(size + 1);
  cost[size] = 0;
  const FULL_LENGTH_CAP = 530;
  for (let i = size - 1; i >= 0; i -= 1) {
    let bestCost = 1 + cost[i + 1];
    let bestChoice = null; // null = literal
    if (i <= matchLimit) {
      let reference = previous[i];
      let depth = 0;
      let foundLength = 0;
      let candidates = 0;
      while (reference >= 0 && reference < i && i - reference <= 65535 &&
             depth < maxDepth && candidates < maxCandidates) {
        if (input[reference + foundLength] === input[i + foundLength] &&
            input.readUInt32LE(reference) === input.readUInt32LE(i)) {
          let length = LZ4_MIN_MATCH + lz4CountMatch(input, reference + LZ4_MIN_MATCH, i + LZ4_MIN_MATCH, size);
          if (i + length > size - 5) length = size - 5 - i;
          if (length >= LZ4_MIN_MATCH && length > foundLength) {
            foundLength = length;
            candidates += 1;
            const offset = i - reference;
            const fullMax = Math.min(length, FULL_LENGTH_CAP);
            for (let l = LZ4_MIN_MATCH; l <= fullMax; l += 1) {
              const candidate = 3 + lz4LengthPrice(l) + cost[i + l];
              if (candidate < bestCost) { bestCost = candidate; bestChoice = { len: l, offset }; }
            }
            if (length > fullMax) {
              const candidate = 3 + lz4LengthPrice(length) + cost[i + length];
              if (candidate < bestCost) { bestCost = candidate; bestChoice = { len: length, offset }; }
            }
          }
        }
        reference = previous[reference];
        depth += 1;
      }
    }
    cost[i] = bestCost;
    choice[i] = bestChoice;
  }
  let anchor = 0;
  let cursor = 0;
  while (cursor < size) {
    const step = choice[cursor];
    if (step) {
      lz4EmitSequence(out, input, anchor, cursor - anchor, step.offset, step.len);
      cursor += step.len;
      anchor = cursor;
    } else {
      cursor += 1;
    }
  }
  lz4EmitSequence(out, input, anchor, size - anchor, 0, LZ4_MIN_MATCH);
  return Buffer.from(out);
}

function compressLz4Block(input, level = 12) {
  return level >= 9 ? compressLz4Optimal(input) : compressLz4Greedy(input);
}

function decryptContainer(container, key) {
  if (!Buffer.isBuffer(container) || container.length <= 20) {
    fail('encrypted KFB container must be larger than 20 bytes');
  }
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    fail('AES-256 key must contain 32 bytes');
  }
  const outerHeader = container.subarray(0, 4);
  const iv = container.subarray(4, 20);
  const ciphertext = container.subarray(20);
  const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
  const lz4Block = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  const plaintext = decompressLz4Stored(lz4Block);
  return { outerHeader, iv, ciphertext, lz4Block, plaintext };
}

function readCString(buffer, state) {
  const end = buffer.indexOf(0, state.position);
  if (end < 0) fail('unterminated UnityFS string');
  const value = buffer.toString('utf8', state.position, end);
  state.position = end + 1;
  return value;
}

function decompressUnityBlock(input, expectedSize, compression) {
  if (compression === 0) {
    if (input.length !== expectedSize) fail('UnityFS uncompressed block size mismatch');
    return input;
  }
  if (compression === 1) {
    return decompressLzmaAlone(input, expectedSize);
  }
  if (compression === 2 || compression === 3) {
    return decompressLz4Raw(input, expectedSize);
  }
  fail(`unsupported UnityFS compression type: ${compression}`);
}

const UNITY_KH_KEY_0 = Buffer.from('X@85Pq!6v$lCt7UYsihH3!cPb1P71bo4lX59FXqY!VO$YiYsu!Keu3aVZwi5on5l');
const UNITY_KH_KEY_1 = Buffer.from('hAi5luE8FlyblDdCTQC9uxnj3rkNwd1swrKI7Mx1aDFEe2B5h#3X&s54%GuSeHf@');

function xorRepeating(input, key) {
  const output = Buffer.allocUnsafe(input.length);
  for (let index = 0; index < input.length; index += 1) output[index] = input[index] ^ key[index % key.length];
  return output;
}

function rotateRightRange(input, offset, length, shift) {
  const output = Buffer.from(input);
  if (input.length === 0 || length < 2) return output;
  const start = Math.min(input.length - 1, offset);
  const end = Math.min(input.length, start + length);
  const actualLength = end - start;
  if (actualLength < 2) return output;
  const amount = shift % actualLength;
  if (amount === 0) return output;
  const range = input.subarray(start, end);
  range.subarray(actualLength - amount).copy(output, start);
  range.subarray(0, actualLength - amount).copy(output, start + amount);
  return output;
}

function rotateLeftRange(input, offset, length, shift) {
  if (input.length === 0 || length < 2) return Buffer.from(input);
  const start = Math.min(input.length - 1, offset);
  const end = Math.min(input.length, start + length);
  const actualLength = end - start;
  if (actualLength < 2) return Buffer.from(input);
  const amount = shift % actualLength;
  return rotateRightRange(input, offset, length, amount === 0 ? 0 : actualLength - amount);
}

function decryptUnityKhBlocks(input, blockSize, version) {
  if (version === 0) return xorRepeating(input, UNITY_KH_KEY_0);
  const sizeKey = Buffer.alloc(8);
  sizeKey.writeBigUInt64BE(BigInt(blockSize));
  if (version === 1) return xorRepeating(xorRepeating(input, UNITY_KH_KEY_1), sizeKey);
  if (version !== 2) fail(`unsupported UnityKH encryption version ${version}`);
  const length = input.length;
  if (length === 0) fail('UnityKH encrypted block-info is empty');
  let alignedLength = (length % 7 + 7) % length;
  if (alignedLength === 0) alignedLength = length;
  const key = blockSize % 3 === 0 || blockSize % 5 === 0 || blockSize % 7 === 0
    ? UNITY_KH_KEY_1 : UNITY_KH_KEY_0;
  let shift = (length % 7 + 7) % length;
  if (shift === 0) shift = length;
  let result = rotateRightRange(input, 0, length, shift);
  result = xorRepeating(result, key);
  result = xorRepeating(result, sizeKey);
  let endOffset = (length % 7 + 1) % alignedLength;
  if (endOffset === 0) endOffset = alignedLength;
  for (let offset = 0; offset < length; offset += alignedLength) {
    result = rotateRightRange(result, offset, Math.min(alignedLength, length - offset), endOffset);
  }
  return rotateRightRange(result, 0, length, endOffset);
}

function encryptUnityKhBlocks(input, blockSize, version) {
  if (version === 0) return xorRepeating(input, UNITY_KH_KEY_0);
  const sizeKey = Buffer.alloc(8);
  sizeKey.writeBigUInt64BE(BigInt(blockSize));
  if (version === 1) return xorRepeating(xorRepeating(input, sizeKey), UNITY_KH_KEY_1);
  if (version !== 2) fail(`unsupported UnityKH encryption version ${version}`);
  const length = input.length;
  if (length === 0) fail('UnityKH block-info is empty');
  let alignedLength = (length % 7 + 7) % length;
  if (alignedLength === 0) alignedLength = length;
  const key = blockSize % 3 === 0 || blockSize % 5 === 0 || blockSize % 7 === 0
    ? UNITY_KH_KEY_1 : UNITY_KH_KEY_0;
  let shift = (length % 7 + 7) % length;
  if (shift === 0) shift = length;
  let endOffset = (length % 7 + 1) % alignedLength;
  if (endOffset === 0) endOffset = alignedLength;

  let result = rotateLeftRange(input, 0, length, endOffset);
  for (let offset = 0; offset < length; offset += alignedLength) {
    result = rotateLeftRange(result, offset, Math.min(alignedLength, length - offset), endOffset);
  }
  result = xorRepeating(result, sizeKey);
  result = xorRepeating(result, key);
  return rotateLeftRange(result, 0, length, shift);
}

function normalizeUnityKhBundle(input) {
  const magicEnd = input.indexOf(0);
  if (magicEnd < 0) fail('unterminated Unity bundle signature');
  const originalSignature = input.toString('ascii', 0, magicEnd);
  if (originalSignature === 'UnityFS') {
    return { bundle: input, originalSignature, khEncryptionVersion: null };
  }
  const versions = new Map([['UnityKHFS', 0], ['UnityKHNFS', 1], ['UnityKH1FS', 2]]);
  if (!versions.has(originalSignature)) fail(`unsupported bundle signature: ${originalSignature}`);
  const khEncryptionVersion = versions.get(originalSignature);
  let position = magicEnd;
  if (position + 31 + 12 > input.length) fail('truncated UnityKH header');
  const unityHeader = input.subarray(position, position + 31); position += 31;
  const blockSizeBytes = input.subarray(position, position + 12);
  const blockSize = blockSizeBytes.readUInt32BE(0); position += 12;
  position += khEncryptionVersion === 0 ? 12 : 11;
  if (blockSize === 0 || position + blockSize > input.length) fail('truncated UnityKH encrypted block-info');
  const encryptedBlockInfo = input.subarray(position, position + blockSize);
  const remaining = input.subarray(position + blockSize);
  const decryptedBlockInfo = decryptUnityKhBlocks(encryptedBlockInfo, blockSize, khEncryptionVersion);
  const bundle = Buffer.concat([
    Buffer.from('UnityFS'), unityHeader, blockSizeBytes, Buffer.alloc(14), decryptedBlockInfo, remaining,
  ]);
  return { bundle, originalSignature, khEncryptionVersion, encryptedBlockInfoBytes: blockSize };
}

function extractUnityFsFiles(bundle) {
  const normalized = normalizeUnityKhBundle(bundle);
  bundle = normalized.bundle;
  const state = { position: 0 };
  const signature = readCString(bundle, state);
  if (signature !== 'UnityFS') fail(`unsupported bundle signature: ${signature}`);
  if (state.position + 4 > bundle.length) fail('truncated UnityFS header');
  const formatVersion = bundle.readUInt32BE(state.position); state.position += 4;
  const unityVersion = readCString(bundle, state);
  const revision = readCString(bundle, state);
  if (state.position + 20 > bundle.length) fail('truncated UnityFS size header');
  const declaredSize = bundle.readBigUInt64BE(state.position); state.position += 8;
  const compressedInfoSize = bundle.readUInt32BE(state.position); state.position += 4;
  const uncompressedInfoSize = bundle.readUInt32BE(state.position); state.position += 4;
  const flags = bundle.readUInt32BE(state.position); state.position += 4;
  const blocksInfoAtEnd = (flags & 0x80) !== 0;
  const declaredSizeNumber = Number(declaredSize);
  if (!Number.isSafeInteger(declaredSizeNumber) || declaredSizeNumber > bundle.length) {
    fail(`invalid UnityFS declared size: ${declaredSize}`);
  }
  // UnityFS format 7+ aligns the data/blocks-info region to 16 bytes even
  // when the legacy 0x200 padding bit is clear (the common at-end layout).
  if (formatVersion >= 7 || (flags & 0x200) !== 0) {
    state.position = (state.position + 15) & ~15;
  }
  const infoOffset = blocksInfoAtEnd
    ? declaredSizeNumber - compressedInfoSize
    : state.position;
  if (infoOffset < state.position || infoOffset + compressedInfoSize > bundle.length) {
    fail('truncated UnityFS blocks info');
  }
  const compressedInfo = bundle.subarray(infoOffset, infoOffset + compressedInfoSize);
  if (!blocksInfoAtEnd) state.position += compressedInfoSize;
  const info = decompressUnityBlock(compressedInfo, uncompressedInfoSize, flags & 0x3f);
  if (!blocksInfoAtEnd && (flags & 0x200) !== 0) state.position = (state.position + 15) & ~15;

  const infoState = { position: 16 };
  if (infoState.position + 4 > info.length) fail('truncated UnityFS block table');
  const blockCount = info.readUInt32BE(infoState.position); infoState.position += 4;
  const blocks = [];
  for (let index = 0; index < blockCount; index += 1) {
    if (infoState.position + 10 > info.length) fail('truncated UnityFS block entry');
    const uncompressedSize = info.readUInt32BE(infoState.position); infoState.position += 4;
    const compressedSize = info.readUInt32BE(infoState.position); infoState.position += 4;
    const blockFlags = info.readUInt16BE(infoState.position); infoState.position += 2;
    blocks.push({ uncompressedSize, compressedSize, flags: blockFlags });
  }
  if (infoState.position + 4 > info.length) fail('truncated UnityFS directory count');
  const directoryCount = info.readUInt32BE(infoState.position); infoState.position += 4;
  const directories = [];
  for (let index = 0; index < directoryCount; index += 1) {
    if (infoState.position + 20 > info.length) fail('truncated UnityFS directory entry');
    const offset = Number(info.readBigUInt64BE(infoState.position)); infoState.position += 8;
    const size = Number(info.readBigUInt64BE(infoState.position)); infoState.position += 8;
    const directoryFlags = info.readUInt32BE(infoState.position); infoState.position += 4;
    const name = readCString(info, infoState);
    directories.push({ offset, size, flags: directoryFlags, name });
  }

  const decodedBlocks = [];
  for (const block of blocks) {
    const dataEnd = blocksInfoAtEnd ? infoOffset : declaredSizeNumber;
    if (state.position + block.compressedSize > dataEnd) fail('truncated UnityFS data block');
    const compressed = bundle.subarray(state.position, state.position + block.compressedSize);
    state.position += block.compressedSize;
    decodedBlocks.push(decompressUnityBlock(compressed, block.uncompressedSize, block.flags & 0x3f));
  }
  const data = Buffer.concat(decodedBlocks);
  const files = directories.map((entry) => {
    if (entry.offset + entry.size > data.length) fail(`UnityFS directory exceeds data: ${entry.name}`);
    return { ...entry, data: data.subarray(entry.offset, entry.offset + entry.size) };
  });
  return {
    signature,
    formatVersion,
    unityVersion,
    revision,
    declaredSize: declaredSize.toString(),
    flags,
    blocksInfoAtEnd,
    uncompressedDataBytes: data.length,
    dataCrc32: crc32(data),
    originalSignature: normalized.originalSignature,
    khEncryptionVersion: normalized.khEncryptionVersion,
    encryptedBlockInfoBytes: normalized.encryptedBlockInfoBytes || 0,
    files,
  };
}

function extractTextAssetScript(bundle, textAssetName) {
  const unityFs = extractUnityFsFiles(bundle);
  const nameBytes = Buffer.from(textAssetName, 'utf8');
  const lengthPrefix = Buffer.alloc(4);
  lengthPrefix.writeUInt32LE(nameBytes.length, 0);
  const needle = Buffer.concat([lengthPrefix, nameBytes]);
  for (const file of unityFs.files) {
    let searchPosition = 0;
    while (searchPosition < file.data.length) {
      const candidate = file.data.indexOf(needle, searchPosition);
      if (candidate < 0) break;
      const nameEnd = candidate + needle.length;
      const scriptLengthOffset = (nameEnd + 3) & ~3;
      if (scriptLengthOffset + 4 <= file.data.length) {
        const scriptLength = file.data.readInt32LE(scriptLengthOffset);
        const scriptOffset = scriptLengthOffset + 4;
        if (scriptLength > 20 && scriptOffset + scriptLength <= file.data.length) {
          return {
            unityFs,
            serializedFile: file.name,
            objectOffset: candidate,
            scriptOffset,
            script: file.data.subarray(scriptOffset, scriptOffset + scriptLength),
          };
        }
      }
      searchPosition = candidate + 1;
    }
  }
  fail(`TextAsset not found: ${textAssetName}`);
}

function findTextAssetCandidates(bundle) {
  const unityFs = extractUnityFsFiles(bundle);
  const candidates = [];
  const allowedName = /^[A-Za-z0-9_.\-/]{1,160}$/;
  for (const file of unityFs.files) {
    const data = file.data;
    for (let candidate = 0; candidate + 12 <= data.length; candidate += 1) {
      const nameLength = data.readUInt32LE(candidate);
      if (nameLength < 1 || nameLength > 160 || candidate + 4 + nameLength > data.length) continue;
      const name = data.toString('utf8', candidate + 4, candidate + 4 + nameLength);
      if (!allowedName.test(name)) continue;
      const scriptLengthOffset = (candidate + 4 + nameLength + 3) & ~3;
      if (scriptLengthOffset + 4 > data.length) continue;
      const scriptLength = data.readInt32LE(scriptLengthOffset);
      const scriptOffset = scriptLengthOffset + 4;
      if (scriptLength <= 20 || scriptOffset + scriptLength > data.length) continue;
      candidates.push({
        unityFs,
        textAssetName: name,
        serializedFile: file.name,
        objectOffset: candidate,
        scriptOffset,
        script: data.subarray(scriptOffset, scriptOffset + scriptLength),
      });
    }
  }
  return candidates;
}

function extractDecryptableTextAsset(bundle, key) {
  const valid = [];
  for (const candidate of findTextAssetCandidates(bundle)) {
    try {
      const result = decryptContainer(candidate.script, key);
      valid.push({ candidate, result });
    } catch (_) {
      // Serialized files contain many length-prefixed strings. Only a genuine
      // encrypted TextAsset passes AES-CTR followed by the strict LZ4 checks.
    }
  }
  if (valid.length === 0) fail('no decryptable encrypted TextAsset found in UnityFS bundle');
  if (valid.length > 1) {
    fail(`multiple decryptable TextAssets found: ${valid.map((entry) => entry.candidate.textAssetName).join(', ')}`);
  }
  return valid[0];
}

function alignValue(value, alignment) {
  return Math.ceil(value / alignment) * alignment;
}

function parseSerializedFileObjects(input) {
  if (!Buffer.isBuffer(input) || input.length < 48) fail('serialized file is too short');
  const version = input.readUInt32BE(8);
  if (version < 12 || version > 100) fail(`unsupported serialized file version ${version}`);
  const endian = input[16];
  if (endian !== 0 && endian !== 1) fail(`invalid serialized metadata endian ${endian}`);
  const little = endian === 0;
  let metadataSize;
  let declaredFileSize;
  let dataOffset;
  let metadataOffset;
  let fileSizeOffset;
  if (version >= 22) {
    metadataSize = input.readUInt32BE(20);
    declaredFileSize = Number(input.readBigUInt64BE(24));
    dataOffset = Number(input.readBigUInt64BE(32));
    metadataOffset = 48;
    fileSizeOffset = 24;
  } else {
    metadataSize = input.readUInt32BE(0);
    declaredFileSize = input.readUInt32BE(4);
    dataOffset = input.readUInt32BE(12);
    metadataOffset = 20;
    fileSizeOffset = 4;
  }
  if (!Number.isSafeInteger(declaredFileSize) || declaredFileSize !== input.length) {
    fail(`serialized file size mismatch: header=${declaredFileSize} actual=${input.length}`);
  }
  if (!Number.isSafeInteger(dataOffset) || dataOffset < metadataOffset || dataOffset > input.length) {
    fail(`invalid serialized data offset ${dataOffset}`);
  }
  const metadataEnd = metadataOffset + metadataSize;
  if (metadataEnd > dataOffset || metadataEnd > input.length) fail('serialized metadata exceeds data offset');
  const state = { position: metadataOffset };
  function ensure(count, what) {
    if (!Number.isInteger(count) || count < 0 || state.position + count > metadataEnd) fail(`truncated serialized ${what}`);
  }
  function u8(what) { ensure(1, what); return input[state.position++]; }
  function i16(what) {
    ensure(2, what); const value = little ? input.readInt16LE(state.position) : input.readInt16BE(state.position);
    state.position += 2; return value;
  }
  function i32(what) {
    ensure(4, what); const value = little ? input.readInt32LE(state.position) : input.readInt32BE(state.position);
    state.position += 4; return value;
  }
  function u32(what) {
    ensure(4, what); const value = little ? input.readUInt32LE(state.position) : input.readUInt32BE(state.position);
    state.position += 4; return value;
  }
  function i64(what) {
    ensure(8, what); const value = little ? input.readBigInt64LE(state.position) : input.readBigInt64BE(state.position);
    state.position += 8; return value;
  }
  function cstring(what) {
    const end = input.indexOf(0, state.position);
    if (end < 0 || end >= metadataEnd) fail(`unterminated serialized ${what}`);
    const value = input.toString('utf8', state.position, end);
    state.position = end + 1;
    return value;
  }
  function skip(count, what) { ensure(count, what); state.position += count; }
  function skipSerializedType(enableTypeTree, isRefType = false) {
    const classId = i32('type class ID');
    if (version >= 16) u8('stripped-type flag');
    const scriptTypeIndex = version >= 17 ? i16('script type index') : -1;
    if (version >= 13) {
      if ((isRefType && scriptTypeIndex >= 0) || (!isRefType && classId === 114)) skip(16, 'script ID');
      skip(16, 'type hash');
    }
    if (enableTypeTree) {
      if (version < 12 && version !== 10) fail(`unsupported legacy type tree in serialized version ${version}`);
      const nodeCount = i32('type-tree node count');
      const stringBytes = i32('type-tree string size');
      if (nodeCount < 0 || nodeCount > 1000000 || stringBytes < 0) fail('invalid serialized type-tree size');
      const nodeSize = version >= 19 ? 32 : 24;
      skip(nodeCount * nodeSize, 'type-tree nodes');
      skip(stringBytes, 'type-tree strings');
    }
    if (version >= 21) {
      if (isRefType) {
        cstring('referenced class name'); cstring('referenced namespace'); cstring('referenced assembly');
      } else {
        const dependencyCount = i32('type dependency count');
        if (dependencyCount < 0 || dependencyCount > 1000000) fail('invalid type dependency count');
        skip(dependencyCount * 4, 'type dependencies');
      }
    }
    return { classId };
  }

  const unityVersion = cstring('Unity version');
  const targetPlatform = i32('target platform');
  const enableTypeTree = u8('type-tree flag') !== 0;
  const typeCount = i32('type count');
  if (typeCount < 0 || typeCount > 100000) fail(`invalid serialized type count ${typeCount}`);
  const types = [];
  for (let index = 0; index < typeCount; index += 1) types.push(skipSerializedType(enableTypeTree, false));
  if (version >= 7 && version < 14) i32('big-ID flag');
  const objectCount = i32('object count');
  if (objectCount < 0 || objectCount > 10000000) fail(`invalid serialized object count ${objectCount}`);
  const objects = [];
  for (let index = 0; index < objectCount; index += 1) {
    if (version >= 14) state.position = alignValue(state.position, 4);
    const pathId = version < 14 ? BigInt(i32('path ID')) : i64('path ID');
    const byteStartOffset = state.position;
    const byteStartBig = version >= 22 ? i64('object byte start') : BigInt(u32('object byte start'));
    if (byteStartBig < 0n || byteStartBig > BigInt(Number.MAX_SAFE_INTEGER)) fail(`invalid object byte start ${byteStartBig}`);
    const byteSizeOffset = state.position;
    const byteSize = u32('object byte size');
    const typeId = i32('object type ID');
    if (version < 16) i16('object class ID');
    if (version < 11) i16('destroyed flag');
    if (version >= 11 && version < 17) i16('script type index');
    if (version === 15 || version === 16) u8('stripped object flag');
    if (typeId < 0 || typeId >= types.length) fail(`object type index ${typeId} is outside type table`);
    const byteStart = Number(byteStartBig);
    if (dataOffset + byteStart + byteSize > input.length) fail(`serialized object ${index} exceeds file`);
    objects.push({
      index, pathId: pathId.toString(), byteStart, byteSize, typeId, classId: types[typeId].classId,
      byteStartOffset, byteSizeOffset,
    });
  }
  return {
    version, endian, little, metadataSize, metadataOffset, metadataEnd, dataOffset, fileSizeOffset,
    unityVersion, targetPlatform, enableTypeTree, types, objects,
  };
}

function replaceTextAssetScript(serialized, extraction, replacementScript) {
  const parsed = parseSerializedFileObjects(serialized);
  const target = parsed.objects.find((entry) => parsed.dataOffset + entry.byteStart === extraction.objectOffset);
  if (!target) fail(`TextAsset object table entry not found at ${extraction.objectOffset}`);
  if (target.classId !== 49) fail(`object at ${extraction.objectOffset} has class ID ${target.classId}, expected TextAsset (49)`);
  const objectStart = parsed.dataOffset + target.byteStart;
  const objectEnd = objectStart + target.byteSize;
  if (extraction.scriptOffset - 4 < objectStart || extraction.scriptOffset + extraction.script.length > objectEnd) {
    fail('TextAsset script range is outside serialized object');
  }
  const recordedLength = serialized.readUInt32LE(extraction.scriptOffset - 4);
  if (recordedLength !== extraction.script.length) fail('TextAsset script length changed during extraction');
  // 如果新加密容器与原 TextAsset 脚本长度完全相同，直接原位替换。
  // 这样不会因为重新排列其它 SerializedFile 对象而引入额外 padding，
  // 对“原数据只改内容、不改长度”的场景尤其重要，也更接近原 Bundle 布局。
  if (replacementScript.length === extraction.script.length) {
    const inPlace = Buffer.from(serialized);
    inPlace.writeUInt32LE(replacementScript.length, extraction.scriptOffset - 4);
    replacementScript.copy(inPlace, extraction.scriptOffset);
    const reparsed = parseSerializedFileObjects(inPlace);
    const updatedTarget = reparsed.objects.find((entry) => entry.index === target.index);
    return {
      data: inPlace,
      objectIndex: target.index,
      oldObjectBytes: target.byteSize,
      newObjectBytes: updatedTarget.byteSize,
      oldSerializedBytes: serialized.length,
      newSerializedBytes: inPlace.length,
      inPlace: true,
    };
  }
  const oldTail = serialized.subarray(extraction.scriptOffset + extraction.script.length, objectEnd);
  if (oldTail.length > 8 || oldTail.some((value) => value !== 0)) fail('TextAsset has unsupported data after script bytes');

  const scriptLength = Buffer.alloc(4);
  scriptLength.writeUInt32LE(replacementScript.length, 0);
  let targetBytes = Buffer.concat([
    serialized.subarray(objectStart, extraction.scriptOffset - 4), scriptLength, replacementScript,
  ]);
  targetBytes = Buffer.concat([targetBytes, Buffer.alloc(alignValue(targetBytes.length, 4) - targetBytes.length)]);

  const ordered = [...parsed.objects].sort((a, b) => a.byteStart - b.byteStart);
  const rebuiltParts = [];
  const updates = new Map();
  let dataLength = 0;
  for (const object of ordered) {
    const aligned = alignValue(dataLength, 8);
    if (aligned > dataLength) rebuiltParts.push(Buffer.alloc(aligned - dataLength));
    dataLength = aligned;
    const bytes = object.index === target.index
      ? targetBytes
      : serialized.subarray(parsed.dataOffset + object.byteStart, parsed.dataOffset + object.byteStart + object.byteSize);
    updates.set(object.index, { byteStart: dataLength, byteSize: bytes.length });
    rebuiltParts.push(bytes);
    dataLength += bytes.length;
  }
  const originalObjectsEnd = ordered.reduce((maximum, object) => Math.max(maximum, object.byteStart + object.byteSize), 0);
  const trailing = serialized.subarray(parsed.dataOffset + originalObjectsEnd);
  if (trailing.length > 0) rebuiltParts.push(trailing);

  const headerAndMetadata = Buffer.from(serialized.subarray(0, parsed.dataOffset));
  for (const object of parsed.objects) {
    const update = updates.get(object.index);
    if (parsed.version >= 22) {
      if (parsed.little) headerAndMetadata.writeBigInt64LE(BigInt(update.byteStart), object.byteStartOffset);
      else headerAndMetadata.writeBigInt64BE(BigInt(update.byteStart), object.byteStartOffset);
    } else if (parsed.little) headerAndMetadata.writeUInt32LE(update.byteStart, object.byteStartOffset);
    else headerAndMetadata.writeUInt32BE(update.byteStart, object.byteStartOffset);
    if (parsed.little) headerAndMetadata.writeUInt32LE(update.byteSize, object.byteSizeOffset);
    else headerAndMetadata.writeUInt32BE(update.byteSize, object.byteSizeOffset);
  }
  const rebuilt = Buffer.concat([headerAndMetadata, ...rebuiltParts]);
  if (parsed.version >= 22) rebuilt.writeBigUInt64BE(BigInt(rebuilt.length), parsed.fileSizeOffset);
  else rebuilt.writeUInt32BE(rebuilt.length, parsed.fileSizeOffset);
  const reparsed = parseSerializedFileObjects(rebuilt);
  const updatedTarget = reparsed.objects.find((entry) => entry.index === target.index);
  return {
    data: rebuilt,
    objectIndex: target.index,
    oldObjectBytes: target.byteSize,
    newObjectBytes: updatedTarget.byteSize,
    oldSerializedBytes: serialized.length,
    newSerializedBytes: rebuilt.length,
  };
}

function uint32Be(value) { const output = Buffer.alloc(4); output.writeUInt32BE(value, 0); return output; }
function uint16Be(value) { const output = Buffer.alloc(2); output.writeUInt16BE(value, 0); return output; }
function uint64Be(value) { const output = Buffer.alloc(8); output.writeBigUInt64BE(BigInt(value), 0); return output; }
function cstringBuffer(value) { return Buffer.concat([Buffer.from(value, 'utf8'), Buffer.from([0])]); }

function buildUnityFsBundle(unityFs, replacementFiles, targetCrc = null, buildOptions = {}) {
  const directories = [];
  const dataParts = [];
  let logicalDataLength = 0;
  for (const file of unityFs.files) {
    const data = replacementFiles.get(file.name) || file.data;
    directories.push({ offset: logicalDataLength, size: data.length, flags: file.flags, name: file.name });
    dataParts.push(data);
    logicalDataLength += data.length;
  }
  if (logicalDataLength === 0 || logicalDataLength > 0xffffffff - 4) {
    fail(`UnityFS data size is outside uint32: ${logicalDataLength}`);
  }
  const logicalData = Buffer.concat(dataParts);
  const crc = targetCrc === null
    ? { data: logicalData, fix: Buffer.alloc(0), before: crc32(logicalData), target: null, after: crc32(logicalData) }
    : crc32AppendFix(logicalData, targetCrc);
  const data = crc.data;
  // splitPoints: [start, end]（逻辑数据中的密文区间）。该区间按原始字节
  // 原样存放（flags=0），避免对不可压缩的 AES 密文做 LZ4 反而膨胀 ~0.4%。
  const splitPoints = buildOptions.splitPoints || null;
  const blockMode = buildOptions.blockCompression || false; // false | 'lz4' | 'lzma'
  const segments = [];
  if (splitPoints && blockMode) {
    const [splitStart, splitEnd] = splitPoints;
    if (!(splitStart >= 0 && splitStart < splitEnd && splitEnd <= data.length)) {
      fail(`invalid split points: ${splitPoints}`);
    }
    segments.push({ start: 0, end: splitStart, store: false });
    segments.push({ start: splitStart, end: splitEnd, store: true });
    segments.push({ start: splitEnd, end: data.length, store: false });
  } else {
    segments.push({ start: 0, end: data.length, store: !blockMode });
  }
  const CHUNK_SIZE = 0x20000;
  const blockEntries = [];
  const blockParts = [];
  for (const segment of segments) {
    if (segment.end <= segment.start) continue;
    if (segment.store) {
      for (let offset = segment.start; offset < segment.end; offset += CHUNK_SIZE) {
        const chunk = data.subarray(offset, Math.min(offset + CHUNK_SIZE, segment.end));
        blockEntries.push({ uncompressedSize: chunk.length, compressedSize: chunk.length, flags: 0 });
        blockParts.push(chunk);
      }
    } else {
      for (let offset = segment.start; offset < segment.end; offset += CHUNK_SIZE) {
        const chunk = data.subarray(offset, Math.min(offset + CHUNK_SIZE, segment.end));
        const useLzma = blockMode === 'lzma';
        const compressedChunk = useLzma ? compressLzmaAlone(chunk) : compressLz4Block(chunk, 12);
        if (compressedChunk.length < chunk.length) {
          blockEntries.push({ uncompressedSize: chunk.length, compressedSize: compressedChunk.length, flags: useLzma ? 1 : 3 });
          blockParts.push(compressedChunk);
        } else {
          blockEntries.push({ uncompressedSize: chunk.length, compressedSize: chunk.length, flags: 0 });
          blockParts.push(chunk);
        }
      }
    }
  }
  const storedData = Buffer.concat(blockParts);
  const infoParts = [Buffer.alloc(16), uint32Be(blockEntries.length)];
  for (const entry of blockEntries) {
    infoParts.push(uint32Be(entry.uncompressedSize), uint32Be(entry.compressedSize), uint16Be(entry.flags));
  }
  infoParts.push(uint32Be(directories.length));
  for (const entry of directories) {
    infoParts.push(uint64Be(entry.offset), uint64Be(entry.size), uint32Be(entry.flags), cstringBuffer(entry.name));
  }
  const info = Buffer.concat(infoParts);
  let storedInfo = info;
  let flags = ((unityFs.flags === undefined ? 0x240 : unityFs.flags) & ~0x3f & ~0x80) >>> 0;
  if (buildOptions.compressInfo) {
    const compressedInfo = compressLz4Block(info, 12);
    if (compressedInfo.length < info.length) {
      storedInfo = compressedInfo;
      flags = (flags | 3) >>> 0; // blocks info 块本身走 LZ4HC
    }
  }
  const headerParts = [
    cstringBuffer('UnityFS'), uint32Be(unityFs.formatVersion), cstringBuffer(unityFs.unityVersion),
    cstringBuffer(unityFs.revision), Buffer.alloc(8), uint32Be(storedInfo.length), uint32Be(info.length), uint32Be(flags),
  ];
  let header = Buffer.concat(headerParts);
  if (unityFs.formatVersion >= 7 || (flags & 0x200) !== 0) {
    header = Buffer.concat([header, Buffer.alloc(alignValue(header.length, 16) - header.length)]);
  }
  let afterInfoPadding = 0;
  if ((flags & 0x200) !== 0) afterInfoPadding = alignValue(header.length + storedInfo.length, 16) - (header.length + storedInfo.length);
  const output = Buffer.concat([header, storedInfo, Buffer.alloc(afterInfoPadding), storedData]);
  const sizeOffset = cstringBuffer('UnityFS').length + 4 + cstringBuffer(unityFs.unityVersion).length +
    cstringBuffer(unityFs.revision).length;
  output.writeBigUInt64BE(BigInt(output.length), sizeOffset);
  return { bundle: output, info, storedInfo, data, storedData, blockEntries, logicalDataBytes: logicalData.length, flags, directories, crc };
}

function setUnityFsDeclaredSize(bundle, size) {
  if (!Buffer.isBuffer(bundle) || bundle.length < 16) fail('invalid Unity bundle while updating declared size');
  const signatureEnd = bundle.indexOf(0);
  if (signatureEnd < 0) fail('unterminated Unity bundle signature while updating declared size');
  const state = { position: signatureEnd + 1 };
  if (state.position + 4 > bundle.length) fail('truncated Unity bundle header while updating declared size');
  state.position += 4; // format version
  readCString(bundle, state); // Unity version
  readCString(bundle, state); // revision
  if (state.position + 20 > bundle.length) fail('truncated UnityFS size header while updating declared size');
  bundle.writeBigUInt64BE(BigInt(size), state.position);
  return bundle;
}

function wrapUnityKhBundle(standardBundle, originalSignature, version) {
  if (originalSignature === 'UnityFS') return standardBundle;
  const signatureEnd = standardBundle.indexOf(0);
  if (signatureEnd < 0 || standardBundle.toString('ascii', 0, signatureEnd) !== 'UnityFS') fail('invalid rebuilt UnityFS signature');
  const state = { position: signatureEnd + 1 };
  state.position += 4;
  readCString(standardBundle, state);
  readCString(standardBundle, state);
  state.position += 8;
  const infoFieldsOffset = state.position;
  const infoSize = standardBundle.readUInt32BE(state.position); state.position += 4;
  state.position += 4;
  const flags = standardBundle.readUInt32BE(state.position); state.position += 4;
  if ((flags & 0x80) !== 0) fail('UnityKH writer requires blocks info at the beginning');
  if ((standardBundle.readUInt32BE(signatureEnd + 1)) >= 7 || (flags & 0x200) !== 0) {
    state.position = alignValue(state.position, 16);
  }
  const infoOffset = state.position;
  const info = standardBundle.subarray(infoOffset, infoOffset + infoSize);
  const encryptedInfo = encryptUnityKhBlocks(info, infoSize, version);
  const signature = Buffer.from(originalSignature, 'ascii');
  const standardHeaderBody = standardBundle.subarray(signatureEnd, infoFieldsOffset + 12);
  const customPaddingLength = infoOffset - signature.length - standardHeaderBody.length;
  if (customPaddingLength < 0) fail('UnityKH signature does not fit rebuilt header');
  const wrapped = Buffer.concat([
    signature, standardHeaderBody, Buffer.alloc(customPaddingLength), encryptedInfo,
    standardBundle.subarray(infoOffset + infoSize),
  ]);
  const normalized = normalizeUnityKhBundle(wrapped);
  if (!normalized.bundle.equals(standardBundle)) fail('UnityKH wrap verification mismatch');
  return wrapped;
}

function compressLzmaAlone(input) {
  if (!lzmaWorker) fail('LZMA support requires vendor_lzma.js next to kfb_static_decrypt.js');
  return Buffer.from(lzmaWorker.compress(input, 9));
}

function decompressLzmaAlone(input, expectedSize) {
  if (!lzmaWorker) fail('LZMA block requires vendor_lzma.js next to kfb_static_decrypt.js');
  const output = Buffer.from(lzmaWorker.decompress(input));
  if (output.length !== expectedSize) {
    fail(`LZMA size mismatch: expected ${expectedSize}, decoded ${output.length}`);
  }
  return output;
}

function encodeCompressedLz4Stored(plaintext, compression) {
  const stored = encodeLiteralOnlyLz4Stored(plaintext);
  if (compression !== 'lz4' && compression !== 'lz4hc') return stored;
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32LE(plaintext.length, 0);
  const compressed = compressLz4Block(plaintext, compression === 'lz4hc' ? 12 : 1);
  const candidate = Buffer.concat([prefix, compressed]);
  return candidate.length < stored.length ? candidate : stored;
}

function encodeLiteralOnlyLz4Stored(plaintext) {
  if (plaintext.length > 0xffffffff) {
    fail('KFB input is too large');
  }
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32LE(plaintext.length, 0);
  const extension = [];
  let remaining = Math.max(0, plaintext.length - 15);
  while (remaining >= 255) {
    extension.push(255);
    remaining -= 255;
  }
  if (plaintext.length >= 15) {
    extension.push(remaining);
  }
  const token = Buffer.from([Math.min(15, plaintext.length) << 4]);
  return Buffer.concat([prefix, token, Buffer.from(extension), plaintext]);
}

function encryptContainer(plaintext, key, outerHeader, iv, compression = 'stored') {
  if (!Buffer.isBuffer(key) || key.length !== 32) fail('AES-256 key must contain 32 bytes');
  if (!Buffer.isBuffer(outerHeader) || outerHeader.length !== 4) fail('encrypted container outer header must contain 4 bytes');
  if (!Buffer.isBuffer(iv) || iv.length !== 16) fail('AES-CTR IV must contain 16 bytes');
  const lz4Block = encodeCompressedLz4Stored(plaintext, compression);
  const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
  const ciphertext = Buffer.concat([cipher.update(lz4Block), cipher.final()]);
  return { container: Buffer.concat([outerHeader, iv, ciphertext]), lz4Block, ciphertext };
}

function buildSelfTestContainer(plaintext, key, iv) {
  const header = Buffer.alloc(4);
  header.writeUInt32LE(plaintext.length >>> 0, 0);
  return encryptContainer(plaintext, key, header, iv).container;
}

function readVarint(buffer, state) {
  let value = 0n;
  let shift = 0n;
  const start = state.position;
  while (state.position < buffer.length && shift <= 63n) {
    const byte = buffer[state.position];
    state.position += 1;
    value |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      return { value, bytes: state.position - start };
    }
    shift += 7n;
  }
  fail('truncated or oversized KFB varint');
}

function previewHex(buffer, limit = 64) {
  const preview = buffer.subarray(0, Math.min(limit, buffer.length)).toString('hex');
  return buffer.length > limit ? `${preview}...` : preview;
}

function decodeUtf8(buffer) {
  const text = buffer.toString('utf8');
  const replacementCount = [...text].filter((character) => character === '\ufffd').length;
  return replacementCount === 0 ? text : null;
}

function inspectKfb(buffer, maxDepth = 2, depth = 0) {
  const state = { position: 0 };
  const fields = [];
  while (state.position < buffer.length) {
    const fieldOffset = state.position;
    const header = readVarint(buffer, state).value;
    const wireType = Number(header & 7n);
    const fieldNumberBig = header >> 3n;
    if (fieldNumberBig <= 0n || fieldNumberBig > 0x7fffffffn || wireType > 7) {
      fail(`invalid KFB field header at offset ${fieldOffset}`);
    }
    const field = {
      offset: fieldOffset,
      fieldNumber: Number(fieldNumberBig),
      wireType,
      wireName: WIRE_NAMES[wireType],
    };

    if (wireType === 0) {
      const variant = readVarint(buffer, state).value;
      field.valueUnsigned = variant.toString();
      field.valueZigZag = ((variant >> 1n) ^ (-(variant & 1n))).toString();
    } else if (wireType === 1) {
      if (state.position + 4 > buffer.length) fail('truncated KFB Fixed32');
      field.valueUInt32 = buffer.readUInt32LE(state.position);
      field.valueFloat = buffer.readFloatLE(state.position);
      state.position += 4;
    } else if (wireType === 2) {
      if (state.position + 8 > buffer.length) fail('truncated KFB Fixed64');
      field.valueUInt64 = buffer.readBigUInt64LE(state.position).toString();
      field.valueDouble = buffer.readDoubleLE(state.position);
      state.position += 8;
    } else {
      const lengthBig = readVarint(buffer, state).value;
      if (lengthBig > BigInt(buffer.length - state.position)) {
        fail(`KFB length exceeds input at field ${field.fieldNumber}`);
      }
      const length = Number(lengthBig);
      const payload = buffer.subarray(state.position, state.position + length);
      state.position += length;
      field.length = length;
      if (wireType === 4) {
        const text = decodeUtf8(payload);
        if (text !== null) {
          field.text = text.length > 4096 ? `${text.slice(0, 4096)}...` : text;
        } else {
          field.hex = previewHex(payload);
        }
      } else {
        field.hex = previewHex(payload);
        if (wireType === 3 && depth < maxDepth && payload.length !== 0) {
          try {
            field.objectFields = inspectKfb(payload, maxDepth, depth + 1);
          } catch (_) {
            // Custom KFB objects (for example FScalar) are raw payloads, not
            // nested field streams. Keep their exact bytes for schema decoding.
          }
        }
      }
    }
    field.endOffset = state.position;
    fields.push(field);
  }
  return fields;
}

function makeInspection(buffer, maxDepth) {
  let fields;
  let complete = true;
  let stoppedAt = null;
  let parseError = null;
  try {
    fields = inspectKfb(buffer, maxDepth);
  } catch (error) {
    const match = /offset (\d+)/.exec(error.message);
    if (!match || Number(match[1]) <= 0) {
      throw error;
    }
    stoppedAt = Number(match[1]);
    fields = inspectKfb(buffer.subarray(0, stoppedAt), maxDepth);
    complete = false;
    parseError = error.message;
  }
  const result = {
    schema: 'kfb-wire-v1',
    bytes: buffer.length,
    sha256: sha256(buffer),
    complete,
    fields,
  };
  if (!complete) {
    result.stoppedAt = stoppedAt;
    result.parseError = parseError;
    result.trailingHex = previewHex(buffer.subarray(stoppedAt));
  }
  return result;
}

function detectPlaintextFormat(buffer) {
  let position = 0;
  if (buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf) {
    position = 3;
  }
  while (position < buffer.length &&
         (buffer[position] === 0x20 || buffer[position] === 0x09 ||
          buffer[position] === 0x0a || buffer[position] === 0x0d)) {
    position += 1;
  }
  return position < buffer.length && buffer[position] === 0x3c ? 'xml' : 'kfb-binary';
}

function commandDecrypt(positional, options) {
  if (positional.length !== 3) usage(2);
  const inputPath = path.resolve(positional[1]);
  const outputPath = positional[2];
  const { key, source } = resolveKey(options);
  const container = fs.readFileSync(inputPath);
  const result = decryptContainer(container, key);
  const absoluteOutput = atomicWrite(outputPath, result.plaintext);
  const plaintextFormat = detectPlaintextFormat(result.plaintext);
  let wireJson = null;
  let wireJsonSkipped = null;
  if (options['wire-json'] && plaintextFormat === 'kfb-binary') {
    const maxDepth = Number(options['max-depth'] || 2);
    const inspection = makeInspection(result.plaintext, maxDepth);
    wireJson = atomicWrite(options['wire-json'], `${JSON.stringify(inspection, null, 2)}\n`);
  } else if (options['wire-json']) {
    wireJsonSkipped = 'plaintext_is_xml';
  }
  process.stdout.write(`${JSON.stringify({
    command: 'decrypt',
    input: inputPath,
    output: absoluteOutput,
    wireJson,
    wireJsonSkipped,
    plaintextFormat,
    encryptedBytes: container.length,
    aesPlaintextBytes: result.lz4Block.length,
    decryptedBytes: result.plaintext.length,
    outerHeaderHex: result.outerHeader.toString('hex'),
    ivHex: result.iv.toString('hex'),
    keySource: source,
    keySummary: keySummary(key),
    sha256: sha256(result.plaintext),
  }, null, 2)}\n`);
}

function commandDecryptBundle(positional, options) {
  if (positional.length !== 4) usage(2);
  const bundlePath = path.resolve(positional[1]);
  const textAssetName = positional[2];
  const outputPath = positional[3];
  const { key, source } = resolveKey(options);
  const bundle = fs.readFileSync(bundlePath);
  let extracted;
  let result;
  if (textAssetName.toLowerCase() === 'auto') {
    const automatic = extractDecryptableTextAsset(bundle, key);
    extracted = automatic.candidate;
    result = automatic.result;
  } else {
    extracted = extractTextAssetScript(bundle, textAssetName);
    result = decryptContainer(extracted.script, key);
  }
  const absoluteOutput = atomicWrite(outputPath, result.plaintext);
  const plaintextFormat = detectPlaintextFormat(result.plaintext);
  let wireJson = null;
  let wireJsonSkipped = null;
  if (options['wire-json'] && plaintextFormat === 'kfb-binary') {
    const maxDepth = Number(options['max-depth'] || 2);
    const inspection = makeInspection(result.plaintext, maxDepth);
    wireJson = atomicWrite(options['wire-json'], `${JSON.stringify(inspection, null, 2)}\n`);
  } else if (options['wire-json']) {
    wireJsonSkipped = 'plaintext_is_xml';
  }
  process.stdout.write(`${JSON.stringify({
    command: 'decrypt-bundle',
    bundle: bundlePath,
    textAssetName: extracted.textAssetName || textAssetName,
    containerSignature: extracted.unityFs.originalSignature,
    khEncryptionVersion: extracted.unityFs.khEncryptionVersion,
    encryptedBlockInfoBytes: extracted.unityFs.encryptedBlockInfoBytes,
    serializedFile: extracted.serializedFile,
    textAssetObjectOffset: extracted.objectOffset,
    encryptedScriptBytes: extracted.script.length,
    output: absoluteOutput,
    wireJson,
    wireJsonSkipped,
    plaintextFormat,
    decryptedBytes: result.plaintext.length,
    outerHeaderHex: result.outerHeader.toString('hex'),
    ivHex: result.iv.toString('hex'),
    keySource: source,
    keySummary: keySummary(key),
    sha256: sha256(result.plaintext),
  }, null, 2)}\n`);
}

function writeDecodedOutputs(plaintext, outputBase, options, inputDetails) {
  if (detectPlaintextFormat(plaintext) !== 'kfb-binary') {
    fail('decode requires binary KFB plaintext; use decrypt/decrypt-bundle for legacy XML assets');
  }
  const defaultSchema = path.join(__dirname, 'kfb_schema.json');
  const loaded = kfbDecoder.loadSchema(options.schema, defaultSchema);
  const loadedLayout = readableAdapter.loadDumpLayout(options['dump-layout'], path.join(__dirname, 'kfb_dump_layout.json'));
  const decoded = kfbDecoder.decodeKfb(plaintext, loaded.schema);
  const outputBaseAbsolute = path.resolve(outputBase);
  const plaintextHash = sha256(plaintext);
  const runtimeJson = readableAdapter.semanticToRuntimeJson(decoded.semantic, loaded.schema, loadedLayout.layout);
  const jsonPath = atomicWrite(`${outputBaseAbsolute}.json`, `${JSON.stringify(runtimeJson, null, 2)}\n`);
  const semanticJsonPath = atomicWrite(`${outputBaseAbsolute}.semantic.json`, `${JSON.stringify(decoded.semantic, null, 2)}\n`);
  const xml = readableAdapter.semanticToLegacyXml(decoded.semantic, loaded.schema, plaintextHash);
  const xmlPath = atomicWrite(`${outputBaseAbsolute}.xml`, xml);
  return {
    ...inputDetails,
    schema: loaded.path,
    dumpLayout: loadedLayout.path,
    rootType: loaded.schema.rootType,
    json: jsonPath,
    xml: xmlPath,
    semanticJson: semanticJsonPath,
    jsonFormat: readableAdapter.FORMAT_NAME,
    xmlFormat: 'AnimationData KFB-readable-v1',
    decryptedBytes: plaintext.length,
    sha256: plaintextHash,
    coverage: decoded.coverage,
  };
}

function commandDecodeBundle(positional, options) {
  if (positional.length !== 4) usage(2);
  const bundlePath = path.resolve(positional[1]);
  const textAssetName = positional[2];
  const outputBase = positional[3];
  const { key, source } = resolveKey(options);
  const bundle = fs.readFileSync(bundlePath);
  let extracted;
  let result;
  if (textAssetName.toLowerCase() === 'auto') {
    const automatic = extractDecryptableTextAsset(bundle, key);
    extracted = automatic.candidate;
    result = automatic.result;
  } else {
    extracted = extractTextAssetScript(bundle, textAssetName);
    result = decryptContainer(extracted.script, key);
  }
  const report = writeDecodedOutputs(result.plaintext, outputBase, options, {
    command: 'decode-bundle',
    bundle: bundlePath,
    textAssetName: extracted.textAssetName || textAssetName,
    containerSignature: extracted.unityFs.originalSignature,
    khEncryptionVersion: extracted.unityFs.khEncryptionVersion,
    encryptedBlockInfoBytes: extracted.unityFs.encryptedBlockInfoBytes,
    serializedFile: extracted.serializedFile,
    textAssetObjectOffset: extracted.objectOffset,
    encryptedScriptBytes: extracted.script.length,
    keySource: source,
    keySummary: keySummary(key),
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

function commandDecode(positional, options) {
  if (positional.length !== 3) usage(2);
  const inputPath = path.resolve(positional[1]);
  const plaintext = fs.readFileSync(inputPath);
  const report = writeDecodedOutputs(plaintext, positional[2], options, {
    command: 'decode', input: inputPath,
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

function readEncodingInput(inputPath, schema, layout) {
  const absolute = path.resolve(inputPath);
  const text = fs.readFileSync(absolute, 'utf8').replace(/^\uFEFF/, '');
  let semantic;
  let format;
  if (text.trimStart().startsWith('<')) {
    semantic = readableAdapter.legacyXmlToSemantic(text, schema);
    format = 'legacy-xml';
  } else {
    const document = JSON.parse(text);
    format = readableAdapter.detectJsonFormat(document);
    semantic = format === 'runtime-json'
      ? readableAdapter.runtimeJsonToSemantic(document, schema, layout)
      : document;
  }
  if (!semantic || typeof semantic !== 'object' || Array.isArray(semantic)) fail('semantic JSON root must be an object');
  return { path: absolute, semantic, format };
}

function canonicalAnimationCurveText(value) {
  if (typeof value !== 'string') return value;
  const sections = value.split('|');
  if (sections.length < 3 || !/^-?\d+$/.test(sections[0]) ||
      !/^-?\d+$/.test(sections[1]) || !/^\d+$/.test(sections[2])) return value;
  const count = Number(sections[2]);
  if (!Number.isSafeInteger(count) || count < 0 || sections.length !== count + 3) return value;
  for (let index = 0; index < count; index += 1) {
    const components = sections[index + 3].split(',');
    if (components.length !== 7 || components.some((item) =>
      item.trim() === '' || !Number.isFinite(Number(item)))) return value;
  }
  // KFBSerializer/Single.ToString may emit E-09 while JavaScript emits E-9.
  // Both spellings encode the same float32 bits, so compare their canonical form.
  return value.replace(/([eE][+-])0+(\d+)/g, '$1$2');
}

function canonicalSemantic(value) {
  if (Array.isArray(value)) return value.map(canonicalSemantic);
  if (value && typeof value === 'object') {
    const output = {};
    for (const key of Object.keys(value).sort()) output[key] = canonicalSemantic(value[key]);
    return output;
  }
  if (typeof value === 'string') return canonicalAnimationCurveText(value);
  return value;
}

function semanticEquals(left, right) {
  return JSON.stringify(canonicalSemantic(left)) === JSON.stringify(canonicalSemantic(right));
}

function commandEncode(positional, options) {
  if (positional.length !== 3) usage(2);
  const defaultSchema = path.join(__dirname, 'kfb_schema.json');
  const loaded = kfbDecoder.loadSchema(options.schema, defaultSchema);
  const loadedLayout = readableAdapter.loadDumpLayout(options['dump-layout'], path.join(__dirname, 'kfb_dump_layout.json'));
  const input = readEncodingInput(positional[1], loaded.schema, loadedLayout.layout);
  const encoded = kfbDecoder.encodeKfb(input.semantic, loaded.schema);
  const decoded = kfbDecoder.decodeKfb(encoded, loaded.schema);
  if (!semanticEquals(input.semantic, decoded.semantic)) fail('encoded KFB semantic round-trip mismatch');
  const output = atomicWrite(positional[2], encoded);
  process.stdout.write(`${JSON.stringify({
    command: 'encode', input: input.path, inputFormat: input.format, output, schema: loaded.path,
    dumpLayout: loadedLayout.path, rootType: loaded.schema.rootType,
    encodedBytes: encoded.length, sha256: sha256(encoded), semanticRoundTrip: true, coverage: decoded.coverage,
  }, null, 2)}\n`);
}

function commandEncodeBundle(positional, options) {
  if (positional.length !== 5) usage(2);
  const bundlePath = path.resolve(positional[1]);
  const requestedName = positional[2];
  const outputPath = path.resolve(positional[4]);
  if (bundlePath === outputPath) fail('encode-bundle output must differ from the source bundle');
  const defaultSchema = path.join(__dirname, 'kfb_schema.json');
  const loaded = kfbDecoder.loadSchema(options.schema, defaultSchema);
  const loadedLayout = readableAdapter.loadDumpLayout(options['dump-layout'], path.join(__dirname, 'kfb_dump_layout.json'));
  const input = readEncodingInput(positional[3], loaded.schema, loadedLayout.layout);
  const { key, source } = resolveKey(options);
  const bundle = fs.readFileSync(bundlePath);
  let extracted;
  let decrypted;
  if (requestedName.toLowerCase() === 'auto') {
    const automatic = extractDecryptableTextAsset(bundle, key);
    extracted = automatic.candidate;
    decrypted = automatic.result;
  } else {
    extracted = extractTextAssetScript(bundle, requestedName);
    decrypted = decryptContainer(extracted.script, key);
  }
  const textAssetName = extracted.textAssetName || requestedName;
  const encodedKfb = kfbDecoder.encodeKfb(input.semantic, loaded.schema);
  const encodedDecoded = kfbDecoder.decodeKfb(encodedKfb, loaded.schema);
  if (!semanticEquals(input.semantic, encodedDecoded.semantic)) fail('encoded KFB semantic round-trip mismatch');
  const matchSize = Boolean(options['match-size']);
  const encrypted = encryptContainer(encodedKfb, key, decrypted.outerHeader, decrypted.iv,
    matchSize ? 'lz4hc' : 'stored');
  const serializedFile = extracted.unityFs.files.find((file) => file.name === extracted.serializedFile);
  if (!serializedFile) fail(`serialized file disappeared: ${extracted.serializedFile}`);
  const replacement = replaceTextAssetScript(serializedFile.data, extracted, encrypted.container);
  const replacements = new Map([[serializedFile.name, replacement.data]]);
  if (process.env.KFB_DEBUG_DUMP) {
    fs.writeFileSync(process.env.KFB_DEBUG_DUMP + '.serialized', replacement.data);
    fs.writeFileSync(process.env.KFB_DEBUG_DUMP + '.container', encrypted.container);
    console.error('DEBUG_DUMP scriptOffset=%d containerBytes=%d serializedBytes=%d',
      extracted.scriptOffset, encrypted.container.length, replacement.data.length);
  }
  // match-size 模式默认跳过 CRC 修复（游戏只校验文件大小，修复字节会占体积）；
  // 显式传 --crc 时仍按指定 CRC 修复。
  const crcTarget = options.crc !== undefined
    ? resolveBundleCrcTarget(bundlePath, extracted.unityFs.dataCrc32, options)
    : (matchSize
      ? { value: null, source: 'disabled-match-size' }
      : resolveBundleCrcTarget(bundlePath, extracted.unityFs.dataCrc32, options));
  // match-size 模式下计算密文在逻辑数据中的区间，让该区间整块原样存放
  let splitPoints = null;
  if (matchSize) {
    let fileOffset = 0;
    for (const file of extracted.unityFs.files) {
      if (file.name === serializedFile.name) break;
      fileOffset += (replacements.get(file.name) || file.data).length;
    }
    const containerStartInFile = extracted.scriptOffset - 4;
    splitPoints = [fileOffset + containerStartInFile,
      fileOffset + containerStartInFile + encrypted.container.length];
  }
  const buildVariant = (blockMode, compressInfo, useSplitPoints = true) => buildUnityFsBundle(extracted.unityFs, replacements,
    crcTarget.value, { blockCompression: blockMode, compressInfo, splitPoints: useSplitPoints ? splitPoints : null });
  let standard;
  let outputBundle;
  let outputShell;
  let matchSizeInfo = null;
  if (matchSize) {
    const targetBytes = bundle.length;
    // 候选按“最接近原版格式”排序：先 KH 壳后裸 UnityFS、先 LZ4 后 LZMA、
    // 每种先不压缩 blockinfo；LZMA 只配压缩 blockinfo（省那 16 字节无意义）。
    // 优先生成与已知可加载包一致的标准 UnityFS + 单 LZMA block 布局；
    // 其次才尝试 LZ4/UnityKH 等兼容候选。match-size 只负责控制最终物理长度，
    // 不应该为了省几个字节而优先选择不同的 Bundle 壳/分块布局。
    const shells = options.unityfs ? ['unityfs'] : ['unityfs', 'unitykh'];
    const strategies = [
      { shell: 'unityfs', blockMode: 'lzma', compressInfo: false, useSplitPoints: false },
      { shell: 'unityfs', blockMode: 'lz4', compressInfo: false, useSplitPoints: false },
      { shell: 'unityfs', blockMode: 'lzma', compressInfo: false, useSplitPoints: true },
      { shell: 'unityfs', blockMode: 'lz4', compressInfo: false, useSplitPoints: true },
      { shell: 'unityfs', blockMode: 'lzma', compressInfo: true, useSplitPoints: false },
      { shell: 'unityfs', blockMode: 'lz4', compressInfo: true, useSplitPoints: false },
      { shell: 'unitykh', blockMode: 'lzma', compressInfo: false, useSplitPoints: false },
      { shell: 'unitykh', blockMode: 'lz4', compressInfo: false, useSplitPoints: false },
      { shell: 'unitykh', blockMode: 'lzma', compressInfo: false, useSplitPoints: true },
      { shell: 'unitykh', blockMode: 'lz4', compressInfo: false, useSplitPoints: true },
    ].filter((strategy) => shells.includes(strategy.shell));
    const candidates = [];
    for (const strategy of strategies) {
      if (strategy.blockMode === 'lzma' && !lzmaWorker) continue;
      const built = buildVariant(strategy.blockMode, strategy.compressInfo, strategy.useSplitPoints);
      if (strategy.shell === 'unityfs') {
        candidates.push({ ...strategy, bundle: built.bundle, built });
      } else {
        candidates.push({
          ...strategy, built,
          bundle: wrapUnityKhBundle(built.bundle, extracted.unityFs.originalSignature,
            extracted.unityFs.khEncryptionVersion),
        });
      }
    }
    let chosen = null;
    for (const candidate of candidates) {
      if (candidate.bundle.length <= targetBytes) { chosen = candidate; break; }
    }
    if (!chosen) {
      fail(`match-size: 重打包结果大于原包 ${targetBytes} 字节（` +
        candidates.map((candidate) =>
          `${candidate.shell}+${candidate.blockMode}${candidate.compressInfo ? '+压缩info' : ''}${candidate.useSplitPoints ? '+split' : '+nosplit'}=${candidate.bundle.length}`).join(', ') +
        '）。请减小 JSON 修改量，或不使用 --match-size。');
    }
    standard = chosen.built;
    const unpaddedBytes = chosen.bundle.length;
    outputBundle = unpaddedBytes === targetBytes
      ? Buffer.from(chosen.bundle)
      : Buffer.concat([chosen.bundle, Buffer.alloc(targetBytes - unpaddedBytes)]);
    // match-size 的尾部补零属于物理文件布局的一部分；UnityFS Header
    // 中的 declared fileSize 必须同步改成最终文件长度，不能只补文件尾。
    // 否则 Header 会继续声明 unpaddedBytes，游戏侧若严格校验文件长度会拒绝加载。
    if (outputBundle.length !== targetBytes) fail('match-size: 输出文件长度修复失败');
    setUnityFsDeclaredSize(outputBundle, outputBundle.length);
    outputShell = chosen.shell;
    matchSizeInfo = {
      enabled: true,
      targetBytes,
      unpaddedBytes,
      paddingBytes: targetBytes - unpaddedBytes,
      declaredSizeBytes: outputBundle.length,
      shell: outputShell,
      blockMode: chosen.blockMode,
      compressedBlockInfo: chosen.compressInfo,
      useSplitPoints: chosen.useSplitPoints,
      blocks: standard.blockEntries,
      candidates: candidates.map((candidate) => ({
        shell: candidate.shell,
        blockMode: candidate.blockMode,
        compressInfo: candidate.compressInfo,
        bytes: candidate.bundle.length,
      })),
    };
  } else {
    standard = buildVariant(false, false);
    outputBundle = options.unityfs
      ? standard.bundle
      : wrapUnityKhBundle(standard.bundle, extracted.unityFs.originalSignature,
        extracted.unityFs.khEncryptionVersion);
    outputShell = options.unityfs ? 'unityfs' : 'unitykh';
  }
  const absoluteOutput = atomicWrite(outputPath, outputBundle);

  const reopened = extractTextAssetScript(outputBundle, textAssetName);
  if (matchSize && Number(reopened.unityFs.declaredSize) !== outputBundle.length) {
    fail(`输出 bundle declaredSize 不匹配: header=${reopened.unityFs.declaredSize}, actual=${outputBundle.length}`);
  }
  if (options.unityfs && reopened.unityFs.originalSignature !== 'UnityFS') {
    fail(`--unityfs output signature mismatch: ${reopened.unityFs.originalSignature}`);
  }
  const reopenedDecrypted = decryptContainer(reopened.script, key);
  if (!reopenedDecrypted.plaintext.equals(encodedKfb)) fail('output bundle KFB bytes differ after reopen');
  if (crcTarget.value !== null && reopened.unityFs.dataCrc32 !== crcTarget.value) {
    fail(`output bundle CRC32 mismatch: expected ${crc32Hex(crcTarget.value)}, got ${crc32Hex(reopened.unityFs.dataCrc32)}`);
  }
  const reopenedDecoded = kfbDecoder.decodeKfb(reopenedDecrypted.plaintext, loaded.schema);
  if (!semanticEquals(input.semantic, reopenedDecoded.semantic)) fail('output bundle semantic verification mismatch');
  process.stdout.write(`${JSON.stringify({
    command: 'encode-bundle',
    bundle: bundlePath,
    input: input.path,
    inputFormat: input.format,
    output: absoluteOutput,
    textAssetName,
    containerSignature: extracted.unityFs.originalSignature,
    khEncryptionVersion: extracted.unityFs.khEncryptionVersion,
    outputContainerSignature: reopened.unityFs.originalSignature,
    outputKhEncryptionVersion: reopened.unityFs.khEncryptionVersion,
    serializedFile: extracted.serializedFile,
    schema: loaded.path,
    dumpLayout: loadedLayout.path,
    rootType: loaded.schema.rootType,
    keySource: source,
    keySummary: keySummary(key),
    originalBundleBytes: bundle.length,
    outputBundleBytes: outputBundle.length,
    originalKfbBytes: decrypted.plaintext.length,
    encodedKfbBytes: encodedKfb.length,
    encodedKfbSha256: sha256(encodedKfb),
    originalEncryptedScriptBytes: extracted.script.length,
    outputEncryptedScriptBytes: encrypted.container.length,
    lz4StoredBytes: encrypted.lz4Block.length,
    originalSerializedBytes: replacement.oldSerializedBytes,
    outputSerializedBytes: replacement.newSerializedBytes,
    textAssetObjectIndex: replacement.objectIndex,
    originalTextAssetObjectBytes: replacement.oldObjectBytes,
    outputTextAssetObjectBytes: replacement.newObjectBytes,
    standardUnityFsFlags: `0x${standard.flags.toString(16)}`,
    crc32: {
      source: crcTarget.source,
      original: crc32Hex(extracted.unityFs.dataCrc32),
      beforeFix: crc32Hex(standard.crc.before),
      target: crcTarget.value === null ? null : crc32Hex(crcTarget.value),
      fixBytesHex: standard.crc.fix.toString('hex'),
      output: crc32Hex(reopened.unityFs.dataCrc32),
      matches: crcTarget.value === null ? null : reopened.unityFs.dataCrc32 === crcTarget.value,
    },
    matchSize: matchSizeInfo,
    lz4Mode: matchSize ? 'lz4hc(optimal)' : 'stored',
    verification: {
      outputBundleSha256: sha256(outputBundle),
      reopenedTextAsset: reopened.textAssetName || textAssetName,
      reopenedKfbBytes: reopenedDecrypted.plaintext.length,
      reopenedKfbSha256: sha256(reopenedDecrypted.plaintext),
      kfbByteIdentical: reopenedDecrypted.plaintext.equals(encodedKfb),
      semanticRoundTrip: true,
      coverage: reopenedDecoded.coverage,
    },
  }, null, 2)}\n`);
}

function commandBuildLayout(positional, options) {
  if (positional.length !== 3) usage(2);
  const defaultSchema = path.join(__dirname, 'kfb_schema.json');
  const loaded = kfbDecoder.loadSchema(options.schema, defaultSchema);
  const dumpPath = path.resolve(positional[1]);
  const layout = readableAdapter.buildDumpLayout(dumpPath, loaded.schema);
  const output = atomicWrite(positional[2], `${JSON.stringify(layout, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({
    command: 'build-layout', dump: dumpPath, dumpSha256: layout.source_sha256,
    schema: loaded.path, output, typeCount: layout.type_count,
  }, null, 2)}\n`);
}

function commandCrcInfo(positional, options) {
  if (positional.length !== 2) usage(2);
  const bundlePath = path.resolve(positional[1]);
  const unityFs = extractUnityFsFiles(fs.readFileSync(bundlePath));
  const target = resolveBundleCrcTarget(bundlePath, unityFs.dataCrc32, options);
  process.stdout.write(`${JSON.stringify({
    command: 'crc-info',
    bundle: bundlePath,
    containerSignature: unityFs.originalSignature,
    khEncryptionVersion: unityFs.khEncryptionVersion,
    uncompressedDataBytes: unityFs.uncompressedDataBytes,
    crc32: crc32Hex(unityFs.dataCrc32),
    targetCrc32: crc32Hex(target.value),
    targetSource: target.source,
    matches: unityFs.dataCrc32 === target.value,
  }, null, 2)}\n`);
}

function commandDecoderSelfTest(positional) {
  if (positional.length !== 1) usage(2);
  const result = kfbDecoder.runSyntheticSelfTest();
  process.stdout.write(`${JSON.stringify({ command: 'decoder-self-test', passed: true, ...result }, null, 2)}\n`);
}

function commandInspect(positional, options) {
  if (positional.length !== 3) usage(2);
  const inputPath = path.resolve(positional[1]);
  const outputPath = positional[2];
  const input = fs.readFileSync(inputPath);
  const maxDepth = Number(options['max-depth'] || 2);
  const inspection = makeInspection(input, maxDepth);
  const absoluteOutput = atomicWrite(outputPath, `${JSON.stringify(inspection, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({
    command: 'inspect',
    input: inputPath,
    output: absoluteOutput,
    bytes: input.length,
    rootFields: inspection.fields.length,
    sha256: inspection.sha256,
  }, null, 2)}\n`);
}

function commandSelfTest(positional) {
  if (positional.length !== 2) usage(2);
  const inputPath = path.resolve(positional[1]);
  const plaintext = fs.readFileSync(inputPath);
  const key = crypto.createHash('sha256').update('kfb-static-self-test-key-v1').digest();
  const iv = crypto.createHash('sha256').update('kfb-static-self-test-iv-v1').digest().subarray(0, 16);
  const container = buildSelfTestContainer(plaintext, key, iv);
  const result = decryptContainer(container, key);
  const originalHash = sha256(plaintext);
  const decryptedHash = sha256(result.plaintext);
  if (!plaintext.equals(result.plaintext)) {
    fail('self-test round trip mismatch');
  }
  const inspection = makeInspection(result.plaintext, 1);
  process.stdout.write(`${JSON.stringify({
    command: 'self-test',
    input: inputPath,
    roundTrip: true,
    plaintextBytes: plaintext.length,
    encryptedFixtureBytes: container.length,
    originalSha256: originalHash,
    decryptedSha256: decryptedHash,
    rootFields: inspection.fields.length,
    structuralParseComplete: inspection.complete,
    structuralParseStoppedAt: inspection.stoppedAt || null,
    firstField: inspection.fields[0] || null,
  }, null, 2)}\n`);
}

function main() {
  const { positional, options } = parseArguments(process.argv.slice(2));
  if (options.help || positional.length === 0) usage(0);
  const command = positional[0];
  if (command === 'decrypt') return commandDecrypt(positional, options);
  if (command === 'decrypt-bundle') return commandDecryptBundle(positional, options);
  if (command === 'decode-bundle') return commandDecodeBundle(positional, options);
  if (command === 'decode') return commandDecode(positional, options);
  if (command === 'encode') return commandEncode(positional, options);
  if (command === 'encode-bundle') return commandEncodeBundle(positional, options);
  if (command === 'build-layout') return commandBuildLayout(positional, options);
  if (command === 'crc-info') return commandCrcInfo(positional, options);
  if (command === 'inspect') return commandInspect(positional, options);
  if (command === 'self-test') return commandSelfTest(positional);
  if (command === 'decoder-self-test') return commandDecoderSelfTest(positional);
  fail(`unknown command: ${command}`);
}

module.exports = {
  parseHexKey, keySummary, sha256, crc32, crc32Hex, crc32AppendFix,
  decryptContainer, encryptContainer, detectPlaintextFormat,
  extractDecryptableTextAsset, extractTextAssetScript,
  replaceTextAssetScript, buildUnityFsBundle, wrapUnityKhBundle,
  semanticEquals, decompressLz4Stored, encodeLiteralOnlyLz4Stored,
  extractUnityFsFiles, normalizeUnityKhBundle, setUnityFsDeclaredSize,
  hasLzmaSupport: () => Boolean(lzmaWorker),
};
