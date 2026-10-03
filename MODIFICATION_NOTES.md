# KFB 工具回打包修正版

本次修改针对 `match-size / 回打包 assetbundle` 的 UnityFS 布局问题。

## 已定位的问题

1. **match-size 补尾部 0 后没有同步修改 UnityFS Header.declaredSize**
   - 异常包：实际 50857 bytes，但 Header.declaredSize = 50744。
   - 现在补零完成后会回写 Header.declaredSize = 最终物理文件长度。
   - 回开校验也会严格检查 declaredSize == 实际长度。

2. **原代码在 match-size 中优先选择 UnityKH + LZ4 + splitPoints**
   - 已知可加载修改包是标准 `UnityFS`。
   - 已知可加载包的 BlockInfo：1 block，LZMA，uncompressed 53732 / compressed 50683，BlockInfo 91 bytes。
   - 原工具异常包：`UnityKH1FS`，3 blocks（LZ4 / stored / LZ4），BlockInfo 111 bytes。
   - 现在 match-size 默认优先尝试：`UnityFS + LZMA + no-split + uncompressed BlockInfo`，再逐级 fallback 到其它布局。

3. **TextAsset 脚本长度不变时原代码会重建整个 SerializedFile**
   - 这可能引入额外对象对齐/padding，使 SerializedFile 无必要增长。
   - 现在如果新脚本长度与原脚本完全一致，则直接原位替换，不重排其它对象。
   - 长度变化时仍使用原来的完整重建逻辑。

## 修改文件

- `web/kfb_static_decrypt.web.js`
- `web/web_core.js`
- `web/dist/kfb_core.bundle.js`（如重新 build 可覆盖）
- `app/assets/www/kfb_core.bundle.js`（Android WebView 实际使用的 bundle 已同步修改）

## 当前验证

- `node --check web/kfb_static_decrypt.web.js`：通过
- `node --check web/web_core.js`：通过
- `app/assets/www/kfb_core.bundle.js` JavaScript syntax：通过

注意：当前环境没有完整 Android SDK / npm 依赖，因此没有在此环境重新签名 APK，也没有伪造“游戏内加载成功”的结论。实际设备测试应重点查看回打包报告中的：

- `shell`
- `blockMode`
- `useSplitPoints`
- `unpaddedBytes`
- `paddingBytes`
- `declaredSizeBytes`

对于这次样本，第一优先目标是生成 `UnityFS + LZMA + no-split`，并确保 Header.declaredSize 与最终文件长度完全相等。
