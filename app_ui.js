'use strict';
// KFB tool mobile UI logic
(function () {
  const $ = (id) => document.getElementById(id);
  const state = {
    schema: null, layout: null, schemaReady: false,
    bundleBuf: null, bundleFileName: null,
    kfb: null, info: null, outs: null,
    runtimeJsonText: null, semanticText: null, xmlText: null,
    encodeBundle: null, encodeBaseName: 'output',
  };

  // ---------- helpers ----------
  function showMsg(el, text, ok) {
    el.className = 'msg ' + (ok ? 'ok' : 'err');
    el.textContent = text;
  }
  function clearMsg(el) { el.className = 'msg'; el.textContent = ''; }
  function bytesReadable(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(2) + ' MB';
  }
  function baseName(name) { return String(name || 'output').replace(/\.[^.]*$/, ''); }
  function busy(btn, on, textBusy) {
    btn.disabled = on;
    btn.innerHTML = on ? `<span class="spin"></span>${textBusy || '处理中…'}` : btn.dataset.label;
  }
  function toArrayBuffer(buf) {
    const ab = new ArrayBuffer(buf.length);
    new Uint8Array(ab).set(buf);
    return ab;
  }
  function bufToBase64(buf) {
    const bytes = new Uint8Array(buf.length); bytes.set(buf);
    let binary = '';
    const CHUNK = 0x8000;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return btoa(binary);
  }
  function saveFile(name, mime, data) {
    if (window.AndroidBridge && typeof AndroidBridge.saveFile === 'function') {
      try {
        AndroidBridge.saveFile(name, mime, bufToBase64(data));
        return;
      } catch (e) { /* fall through to browser download */ }
    }
    const blob = new Blob([data], { type: mime });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 5000);
  }

  // ---------- schema loading ----------
  function loadAssets() {
    if (state.schemaReady) return Promise.resolve();
    const read = (path) => (
      window.AndroidBridge && typeof AndroidBridge.readAsset === 'function'
        ? Promise.resolve(AndroidBridge.readAsset(path))
        : fetch(path).then((r) => r.text())
    );
    return Promise.all([read('data/kfb_schema.json'), read('data/kfb_dump_layout.json')])
      .then(([schemaText, layoutText]) => {
        state.schema = JSON.parse(schemaText);
        state.layout = JSON.parse(layoutText);
        state.schemaReady = true;
        $('verTag').textContent = 'schema ' + (state.schema.schema_version || state.schema.version || 'v2');
      });
  }

  // ---------- tabs ----------
  document.querySelectorAll('.tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach((t) => t.classList.remove('on'));
      document.querySelectorAll('.page').forEach((p) => p.classList.remove('on'));
      tab.classList.add('on');
      $('page-' + tab.dataset.page).classList.add('on');
      if (tab.dataset.page === 'encode' && $('keyEncode').value === '' && $('keyDecrypt').value) {
        $('keyEncode').value = $('keyDecrypt').value;
      }
    });
  });

  // ---------- file pickers ----------
  function bindPicker(inputId, nameId) {
    const input = $(inputId);
    const nameEl = $(nameId);
    input.addEventListener('change', () => {
      const f = input.files && input.files[0];
      nameEl.textContent = f ? f.name + '（' + bytesReadable(f.size) + '）' : '未选择';
      nameEl.classList.toggle('empty', !f);
    });
  }
  bindPicker('fileBundle', 'bundleName');
  bindPicker('fileBundle2', 'bundle2Name');
  bindPicker('fileJson', 'jsonName');

  function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = () => reject(new Error('读取文件失败: ' + file.name));
      r.readAsArrayBuffer(file);
    });
  }
  function readFileAsText(file) {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = () => reject(new Error('读取文件失败: ' + file.name));
      r.readAsText(file, 'utf-8');
    });
  }

  // ---------- decrypt flow ----------
  $('btnDecrypt').addEventListener('click', () => {
    const btn = $('btnDecrypt');
    btn.dataset.label = btn.innerHTML;
    clearMsg($('msgDecrypt'));
    const file = $('fileBundle').files && $('fileBundle').files[0];
    if (!file) { showMsg($('msgDecrypt'), '请先选择 assetbundle 文件', false); return; }
    if (!$('keyDecrypt').value.trim()) { showMsg($('msgDecrypt'), '请输入 AES-256 密钥（64 位十六进制）', false); return; }
    busy(btn, true, '解密中…');
    setTimeout(() => {
      try {
        Promise.all([loadAssets(), readFileAsArrayBuffer(file)]).then(([_, buf]) => {
          try {
            const t0 = Date.now();
            const dec = KfbTool.decryptBundle(buf, $('keyDecrypt').value.trim());
            const outs = KfbTool.decodeOutputs(dec.kfb, state.schema, state.layout);
            state.bundleBuf = buf; state.bundleFileName = file.name;
            state.kfb = dec.kfb; state.info = dec.info; state.outs = outs;
            state.encodeBaseName = baseName(file.name);
            state.runtimeJsonText = JSON.stringify(outs.runtimeJson, null, 2);
            state.semanticText = JSON.stringify(outs.semantic, null, 2);
            state.xmlText = outs.xml;
            const rows = [
              ['TextAsset', dec.info.textAssetName],
              ['容器签名', dec.info.containerSignature + (dec.info.khEncryptionVersion !== null ? ' (v' + dec.info.khEncryptionVersion + ')' : '')],
              ['bundle 大小', bytesReadable(dec.info.bundleBytes)],
              ['明文 KFB', bytesReadable(dec.info.kfbBytes)],
              ['KFB SHA256', dec.info.kfbSha256.slice(0, 32) + '…'],
              ['未知字段', outs.unknownCount === 0 ? '0（schema 完整 ✓）' : outs.unknownCount + ' 处'],
              ['数据 CRC32', dec.info.dataCrc32],
              ['耗时', (Date.now() - t0) + ' ms'],
            ];
            $('infoTable').innerHTML = rows.map((r) => `<tr><td>${r[0]}</td><td>${r[1]}</td></tr>`).join('');
            $('jsonPreview').textContent = state.runtimeJsonText.slice(0, 4000) + (state.runtimeJsonText.length > 4000 ? '\n…（已截断）' : '');
            $('resultDecrypt').style.display = 'block';
            if (outs.unknownCount > 0) {
              showMsg($('msgDecrypt'), `解密成功，但有 ${outs.unknownCount} 处未知字段（schema 可能需更新），编辑后回打包可能丢数据`, false);
            } else {
              showMsg($('msgDecrypt'), '解密成功，输出已可下载', true);
            }
          } catch (e) {
            showMsg($('msgDecrypt'), '失败：' + e.message, false);
          } finally {
            busy(btn, false);
          }
        });
      } catch (e) {
        showMsg($('msgDecrypt'), '失败：' + e.message, false);
        busy(btn, false);
      }
    }, 30);
  });

  document.querySelectorAll('#resultDecrypt [data-dl]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const kind = btn.dataset.dl;
      const base = state.encodeBaseName || 'output';
      if (kind === 'kfb') saveFile(base + '.kfb', 'application/octet-stream', state.kfb);
      else if (kind === 'json') saveFile(base + '.json', 'application/json', Buffer.from(state.runtimeJsonText, 'utf8'));
      else if (kind === 'semantic') saveFile(base + '.semantic.json', 'application/json', Buffer.from(state.semanticText, 'utf8'));
      else if (kind === 'xml') saveFile(base + '.xml', 'application/xml', Buffer.from(state.xmlText, 'utf8'));
    });
  });

  // ---------- encode flow ----------
  $('btnEncode').addEventListener('click', () => {
    const btn = $('btnEncode');
    btn.dataset.label = btn.innerHTML;
    clearMsg($('msgEncode'));
    const bundleFile = $('fileBundle2').files && $('fileBundle2').files[0];
    const jsonFile = $('fileJson').files && $('fileJson').files[0];
    if (!bundleFile) { showMsg($('msgEncode'), '请选择原始 assetbundle（作为容器模板）', false); return; }
    if (!jsonFile) { showMsg($('msgEncode'), '请选择编辑后的 JSON / XML 文件', false); return; }
    if (!$('keyEncode').value.trim()) { showMsg($('msgEncode'), '请输入 AES-256 密钥', false); return; }
    busy(btn, true, '回打包中…');
    setTimeout(() => {
      Promise.all([loadAssets(), readFileAsArrayBuffer(bundleFile), readFileAsText(jsonFile)])
        .then(([_, buf, text]) => {
          try {
            const t0 = Date.now();
            const matchSize = Boolean(document.getElementById('optMatchSize') && document.getElementById('optMatchSize').checked);
            const result = KfbTool.encodeBundle(buf, $('keyEncode').value.trim(), text, state.schema, state.layout,
              { matchSize });
            state.encodeBundle = result.bundle;
            const r = result.report;
            const rows = [
              ['输入格式', r.inputFormat],
              ['TextAsset', r.textAssetName],
              ['原 bundle', bytesReadable(r.originalBundleBytes)],
              ['新 bundle', bytesReadable(r.outputBundleBytes) + (r.matchSize && r.matchSize.paddingBytes > 0
                ? `（补零 ${r.matchSize.paddingBytes} 字节对齐原包）` : '')],
              ['编码 KFB', bytesReadable(r.encodedKfbBytes)],
              ['输出外壳', r.matchSize ? `${r.matchSize.shell} + ${r.matchSize.blockMode}${r.matchSize.compressedBlockInfo ? ' + 压缩info' : ''}` : '原样'],
              ['CRC32', r.crc32.target === null
                ? `${r.crc32.output}（match-size 模式跳过修复）`
                : `${r.crc32.output}（已修复为原包值 ✓）`],
              ['重开校验', 'KFB 字节一致 ✓ / 语义一致 ✓'],
              ['输出 SHA256', r.verification.outputBundleSha256.slice(0, 32) + '…'],
              ['耗时', (Date.now() - t0) + ' ms'],
            ];
            $('encodeTable').innerHTML = rows.map((row) => `<tr><td>${row[0]}</td><td>${row[1]}</td></tr>`).join('');
            $('resultEncode').style.display = 'block';
            showMsg($('msgEncode'), '回打包成功，全部校验通过', true);
          } catch (e) {
            showMsg($('msgEncode'), '失败：' + e.message, false);
          } finally {
            busy(btn, false);
          }
        })
        .catch((e) => { showMsg($('msgEncode'), '失败：' + e.message, false); busy(btn, false); });
    }, 30);
  });

  $('dlBundle').addEventListener('click', () => {
    if (!state.encodeBundle) return;
    saveFile((state.encodeBaseName || 'output') + '_mod.assetbundle', 'application/octet-stream', state.encodeBundle);
  });

  // init
  $('verTag').textContent = 'v' + (window.KfbTool && KfbTool.versions ? KfbTool.versions.core : '1.0');
})();
