'use strict';
// KFB tool web core — browser/node compatible bundle exposing:
//   KfbTool.decryptBundle(bundleBuffer, keyHex)            → decrypt + decode info
//   KfbTool.decodeOutputs(kfbBuffer, schemaObj, layoutObj) → runtime JSON / semantic / XML
//   KfbTool.encodeBundle(bundleBuffer, keyHex, inputText, schemaObj, layoutObj, opts) → repacked bundle
//   KfbTool.crcInfo(bundleBuffer)                           → CRC32 of bundle data area
globalThis.Buffer = globalThis.Buffer || require('buffer/').Buffer;

const cli = require('./kfb_static_decrypt.web.js');
const decoder = require('./kfb_schema_decoder.js');
const adapter = require('./kfb_readable_adapter.js');

function parseKeyInput(keyHex) {
  const cleaned = String(keyHex || '').replace(/[^0-9a-fA-F]/g, '');
  if (cleaned.length !== 64) {
    throw new Error(`AES 密钥必须是 64 位十六进制字符（32 字节），当前 ${cleaned.length} 位`);
  }
  return cli.parseHexKey(cleaned);
}

function parseSchema(schemaObj) {
  return decoder.normalizeSchema(schemaObj);
}

// ---- decrypt: bundle buffer → plaintext KFB ----
function decryptBundle(bundleBuffer, keyHex) {
  const key = parseKeyInput(keyHex);
  const bundle = Buffer.from(bundleBuffer);
  const automatic = cli.extractDecryptableTextAsset(bundle, key);
  const extracted = automatic.candidate;
  const result = automatic.result;
  const info = {
    textAssetName: extracted.textAssetName,
    containerSignature: extracted.unityFs.originalSignature,
    khEncryptionVersion: extracted.unityFs.khEncryptionVersion,
    serializedFile: extracted.serializedFile,
    bundleBytes: bundle.length,
    kfbBytes: result.plaintext.length,
    kfbSha256: cli.sha256(result.plaintext),
    keySummary: cli.keySummary(key),
    dataCrc32: cli.crc32Hex(extracted.unityFs.dataCrc32),
  };
  return { kfb: result.plaintext, info, _internal: { extracted, decrypted: result, key } };
}

// ---- decode: plaintext KFB → runtime JSON / semantic JSON / XML ----
function decodeOutputs(kfbBuffer, schemaObj, layoutObj, lenient = true) {
  const schema = parseSchema(schemaObj);
  const decoded = decoder.decodeKfb(Buffer.from(kfbBuffer), schema, { lenientUnknown: lenient });
  const plaintextHash = cli.sha256(Buffer.from(kfbBuffer));
  const runtimeJson = adapter.semanticToRuntimeJson(decoded.semantic, schema, layoutObj);
  const xml = adapter.semanticToLegacyXml(decoded.semantic, schema, plaintextHash);
  const unknownCount = (decoded.unknownFields || []).length;
  if (lenient && unknownCount > 0) {
    // Non-empty unknown lists cannot be skipped leniently; surface a friendly error.
    const blocking = (decoded.unknownFields || []).some((entry) => /LENIENT-UNSUPPORTED/.test(String(entry.error || entry.detail || '')));
    if (blocking) {
      const first = decoded.unknownFields.find((entry) => /LENIENT-UNSUPPORTED/.test(String(entry.error || entry.detail || '')));
      throw new Error(`存在无法跳过的未知字段（${first ? (first.type || first.path || '?') : '?'}）：schema 需要更新后才能完整解析`);
    }
  }
  return {
    runtimeJson,
    semantic: decoded.semantic,
    xml,
    unknownFields: decoded.unknownFields || [],
    unknownCount,
    coverage: decoded.coverage,
  };
}

// ---- encode: edited JSON + original bundle → repacked bundle ----
function readSemanticInput(inputText, schema, layout) {
  const text = String(inputText).replace(/^\uFEFF/, '');
  if (text.trimStart().startsWith('<')) {
    return { semantic: adapter.legacyXmlToSemantic(text, schema), format: 'legacy-xml' };
  }
  const document = JSON.parse(text);
  const format = adapter.detectJsonFormat(document);
  const semantic = format === 'runtime-json'
    ? adapter.runtimeJsonToSemantic(document, schema, layout)
    : document;
  if (!semantic || typeof semantic !== 'object' || Array.isArray(semantic)) {
    throw new Error('semantic JSON 根节点必须是对象');
  }
  return { semantic, format };
}

function encodeBundle(bundleBuffer, keyHex, inputText, schemaObj, layoutObj, opts = {}) {
  const key = parseKeyInput(keyHex);
  const schema = parseSchema(schemaObj);
  const bundle = Buffer.from(bundleBuffer);

  const automatic = cli.extractDecryptableTextAsset(bundle, key);
  const extracted = automatic.candidate;
  const decrypted = automatic.result;
  const textAssetName = extracted.textAssetName;

  const input = readSemanticInput(inputText, schema, layoutObj);

  const encodedKfb = decoder.encodeKfb(input.semantic, schema);
  const encodedDecoded = decoder.decodeKfb(encodedKfb, schema);
  if (!cli.semanticEquals(input.semantic, encodedDecoded.semantic)) {
    throw new Error('编码后的 KFB 语义校验不一致（semantic round-trip mismatch）');
  }

  const matchSize = Boolean(opts.matchSize);
  const encrypted = cli.encryptContainer(encodedKfb, key, decrypted.outerHeader, decrypted.iv,
    matchSize ? 'lz4hc' : 'stored');
  const serializedFile = extracted.unityFs.files.find((file) => file.name === extracted.serializedFile);
  if (!serializedFile) throw new Error(`serialized file 缺失: ${extracted.serializedFile}`);
  const replacement = cli.replaceTextAssetScript(serializedFile.data, extracted, encrypted.container);
  const replacements = new Map([[serializedFile.name, replacement.data]]);

  // match-size 模式默认跳过 CRC 修复（游戏只校验文件大小，修复字节会占体积）
  const crcTarget = matchSize ? null : (extracted.unityFs.dataCrc32 >>> 0);
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
  const buildVariant = (blockMode, compressInfo, useSplitPoints = true) => cli.buildUnityFsBundle(extracted.unityFs, replacements,
    crcTarget, { blockCompression: blockMode, compressInfo, splitPoints: useSplitPoints ? splitPoints : null });

  let standard;
  let outputBundle;
  let matchSizeInfo = null;
  if (matchSize) {
    const targetBytes = bundle.length;
    // 候选按“最接近原版格式”排序：先 KH 壳后裸 UnityFS、先 LZ4 后 LZMA
    const shells = opts.unityfs ? ['unityfs'] : ['unityfs', 'unitykh'];
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
      if (strategy.blockMode === 'lzma' && !cli.hasLzmaSupport()) continue;
      const built = buildVariant(strategy.blockMode, strategy.compressInfo, strategy.useSplitPoints);
      if (strategy.shell === 'unityfs') {
        candidates.push({ ...strategy, bundle: built.bundle, built });
      } else {
        candidates.push({
          ...strategy, built,
          bundle: cli.wrapUnityKhBundle(built.bundle, extracted.unityFs.originalSignature,
            extracted.unityFs.khEncryptionVersion),
        });
      }
    }
    let chosen = null;
    for (const candidate of candidates) {
      if (candidate.bundle.length <= targetBytes) { chosen = candidate; break; }
    }
    if (!chosen) {
      throw new Error(`match-size: 重打包结果大于原包 ${targetBytes} 字节（`
        + candidates.map((candidate) =>
          `${candidate.shell}+${candidate.blockMode}${candidate.compressInfo ? '+压缩info' : ''}=${candidate.bundle.length}`).join(', ')
        + '）。请减小 JSON 修改量，或不使用“对齐原文件大小”。');
    }
    standard = chosen.built;
    const unpaddedBytes = chosen.bundle.length;
    outputBundle = unpaddedBytes === targetBytes
      ? Buffer.from(chosen.bundle)
      : Buffer.concat([chosen.bundle, Buffer.alloc(targetBytes - unpaddedBytes)]);
    if (outputBundle.length !== targetBytes) {
      throw new Error('对齐原文件大小失败：输出文件长度不正确');
    }
    // 尾部补零后同步修正 UnityFS Header.declaredSize。
    cli.setUnityFsDeclaredSize(outputBundle, outputBundle.length);
    matchSizeInfo = {
      enabled: true,
      targetBytes,
      unpaddedBytes,
      paddingBytes: targetBytes - unpaddedBytes,
      declaredSizeBytes: outputBundle.length,
      shell: chosen.shell,
      blockMode: chosen.blockMode,
      compressedBlockInfo: chosen.compressInfo,
      useSplitPoints: chosen.useSplitPoints,
      candidates: candidates.map((candidate) => ({
        shell: candidate.shell,
        blockMode: candidate.blockMode,
        compressInfo: candidate.compressInfo,
        bytes: candidate.bundle.length,
      })),
    };
  } else {
    standard = buildVariant(false, false);
    outputBundle = opts.unityfs
      ? standard.bundle
      : cli.wrapUnityKhBundle(standard.bundle, extracted.unityFs.originalSignature, extracted.unityFs.khEncryptionVersion);
  }

  // Reopen verification (mirrors CLI encode-bundle checks)
  const reopened = cli.extractTextAssetScript(outputBundle, textAssetName);
  if (matchSize && Number(reopened.unityFs.declaredSize) !== outputBundle.length) {
    throw new Error(`输出 bundle declaredSize 不匹配: header=${reopened.unityFs.declaredSize}, actual=${outputBundle.length}`);
  }
  const reopenedDecrypted = cli.decryptContainer(reopened.script, key);
  if (!reopenedDecrypted.plaintext.equals(encodedKfb)) {
    throw new Error('输出 bundle 重新解密后 KFB 字节不一致');
  }
  if (crcTarget !== null && reopened.unityFs.dataCrc32 !== crcTarget) {
    throw new Error(`输出 bundle CRC32 不匹配: 期望 ${cli.crc32Hex(crcTarget)}, 实际 ${cli.crc32Hex(reopened.unityFs.dataCrc32)}`);
  }
  const reopenedDecoded = decoder.decodeKfb(reopenedDecrypted.plaintext, schema);
  if (!cli.semanticEquals(input.semantic, reopenedDecoded.semantic)) {
    throw new Error('输出 bundle 语义校验失败');
  }

  return {
    bundle: outputBundle,
    report: {
      inputFormat: input.format,
      textAssetName,
      containerSignature: extracted.unityFs.originalSignature,
      khEncryptionVersion: extracted.unityFs.khEncryptionVersion,
      outputContainerSignature: reopened.unityFs.originalSignature,
      originalBundleBytes: bundle.length,
      outputBundleBytes: outputBundle.length,
      originalKfbBytes: decrypted.plaintext.length,
      encodedKfbBytes: encodedKfb.length,
      encodedKfbSha256: cli.sha256(encodedKfb),
      matchSize: matchSizeInfo,
      lz4Mode: matchSize ? 'lz4hc(optimal)' : 'stored',
      crc32: {
        original: cli.crc32Hex(extracted.unityFs.dataCrc32),
        target: crcTarget === null ? null : cli.crc32Hex(crcTarget),
        output: cli.crc32Hex(reopened.unityFs.dataCrc32),
        matches: crcTarget === null ? null : reopened.unityFs.dataCrc32 === crcTarget,
      },
      verification: {
        kfbByteIdentical: true,
        semanticRoundTrip: true,
        outputBundleSha256: cli.sha256(outputBundle),
      },
    },
  };
}

function crcInfo(bundleBuffer) {
  const bundle = Buffer.from(bundleBuffer);
  const unityFs = cli.extractUnityFsFiles(bundle);
  return {
    containerSignature: unityFs.originalSignature,
    khEncryptionVersion: unityFs.khEncryptionVersion,
    dataCrc32: cli.crc32Hex(unityFs.dataCrc32),
    files: unityFs.files.map((file) => file.name),
  };
}

globalThis.KfbTool = {
  decryptBundle,
  decodeOutputs,
  encodeBundle,
  crcInfo,
  normalizeSchema: parseSchema,
  versions: { core: '1.0.0' },
};
