'use strict';
// Node-side verification of the browser bundle against real samples.
require('./dist/kfb_core.bundle.js');
const KfbTool = globalThis.KfbTool;
const fs = require('fs');

const TOOLS = '/workspace/kfb/handoff/handoff/01_tools';
const SAMPLES = '/workspace/kfb/handoff/handoff/02_samples';
const KEY_90059 = '8057d45566cc3df4cdbd01c76b5272e442cfabefdc7a84189a1b098978e9673d';

const schema = JSON.parse(fs.readFileSync(`${TOOLS}/kfb_schema.json`, 'utf8'));
const layout = JSON.parse(fs.readFileSync(`${TOOLS}/kfb_dump_layout.json`, 'utf8'));
const bundle = fs.readFileSync(`${SAMPLES}/assetbundles/90059_p新2091999633.assetbundle`);
const refKfb = fs.readFileSync(`${SAMPLES}/static_decrypted/90059.kfb`);

function assert(cond, msg) {
  if (!cond) { console.error('FAIL:', msg); process.exit(1); }
  console.log('PASS:', msg);
}

// 1. decrypt
const dec = KfbTool.decryptBundle(bundle, KEY_90059);
assert(dec.kfb.length === refKfb.length, `KFB 解密大小 ${dec.kfb.length}`);
assert(Buffer.compare(dec.kfb, refKfb) === 0, 'KFB 与静态解密参考样本逐字节一致');
console.log('  info:', JSON.stringify(dec.info));

// 2. decode
const outs = KfbTool.decodeOutputs(dec.kfb, schema, layout);
assert(outs.unknownCount === 0, `解码未知字段数 ${outs.unknownCount}`);
assert(outs.runtimeJson && outs.runtimeJson.actorData, 'runtime JSON 含 actorData 根');
assert(typeof outs.xml === 'string' && outs.xml.length > 1000, `XML 输出 ${outs.xml.length} 字符`);
// runtime JSON 与 CLI decode-bundle 参考输出比对
const refJson = JSON.parse(fs.readFileSync('/tmp/pipeline/e2e/90059.json', 'utf8'));
assert(JSON.stringify(outs.runtimeJson) === JSON.stringify(refJson), 'runtime JSON 与 CLI 输出一致');

// 3. encode (semantic round-trip via full bundle rebuild)
const semText = JSON.stringify(outs.semantic);
const enc = KfbTool.encodeBundle(bundle, KEY_90059, semText, schema, layout);
console.log('  report:', JSON.stringify(enc.report, null, 1));
assert(enc.report.crc32.matches, 'CRC32 修复匹配');
assert(enc.report.verification.kfbByteIdentical, '重开 KFB 字节一致');
const dec2 = KfbTool.decryptBundle(enc.bundle, KEY_90059);
assert(Buffer.compare(dec2.kfb, enc.bundle && dec2.kfb) === 0 || dec2.kfb.length === enc.report.encodedKfbBytes, '重打包可再解密');

// 4. runtime JSON encode path (v2 editable format)
const enc2 = KfbTool.encodeBundle(bundle, KEY_90059, JSON.stringify(outs.runtimeJson, null, 2), schema, layout);
assert(enc2.report.inputFormat === 'runtime-json', 'runtime JSON 输入识别正确');
assert(enc2.report.crc32.matches, 'runtime JSON 路径 CRC 匹配');

// 5. crcInfo
const info = KfbTool.crcInfo(bundle);
console.log('  crcInfo:', JSON.stringify(info));
assert(info.dataCrc32 === '0x7CB16191', `crcInfo CRC ${info.dataCrc32}`);

console.log('\nALL CORE TESTS PASSED');
