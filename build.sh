#!/bin/bash
# Build KFB工具.apk — WebView shell + bundled JS tool
set -e

SDK=/opt/android-sdk
BT=$SDK/build-tools/34.0.0
PLATFORM=$SDK/platforms/android-34/android.jar
ROOT="$(cd "$(dirname "$0")" && pwd)"
APP=$ROOT/app
WEB=$ROOT/web
BUILD=$ROOT/build
OUT_APK="/workspace/KFB工具.apk"

export JAVA_HOME=/opt/jdk17
export PATH=$JAVA_HOME/bin:$PATH

echo "==> [0/8] rebuild web bundle"
cd $WEB && node build_core.js > /dev/null
cp $WEB/dist/kfb_core.bundle.js $APP/assets/www/kfb_core.bundle.js

rm -rf $BUILD
mkdir -p $BUILD/gen $BUILD/classes

echo "==> [1/8] aapt2 compile resources"
$BT/aapt2 compile --dir $APP/res -o $BUILD/res.zip

echo "==> [2/8] aapt2 link (manifest + resources + assets)"
$BT/aapt2 link -o $BUILD/app.base.apk -I $PLATFORM \
  --manifest $APP/AndroidManifest.xml --java $BUILD/gen \
  -A $APP/assets $BUILD/res.zip --auto-add-overlay

echo "==> [3/8] javac"
javac -source 8 -target 8 -nowarn -encoding UTF-8 \
  -classpath $PLATFORM -d $BUILD/classes \
  $BUILD/gen/com/kfb/tools/R.java $APP/java/com/kfb/tools/MainActivity.java 2>&1 | grep -v "^warning" || true
test -f $BUILD/classes/com/kfb/tools/MainActivity.class

echo "==> [4/8] d8 dex"
$BT/d8 --release --lib $PLATFORM --min-api 21 --output $BUILD \
  $(find $BUILD/classes -name '*.class')

echo "==> [5/8] package classes.dex"
cd $BUILD && zip -q app.base.apk classes.dex

echo "==> [6/8] zipalign"
$BT/zipalign -f 4 $BUILD/app.base.apk $BUILD/app.aligned.apk

echo "==> [7/8] keystore + sign"
if [ ! -f $ROOT/release.keystore ]; then
  keytool -genkeypair -keystore $ROOT/release.keystore -alias kfb \
    -storepass kfb123456 -keypass kfb123456 \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=KFB Tool, OU=Tools, O=KFB, C=CN" 2>/dev/null
fi
$BT/apksigner sign --ks $ROOT/release.keystore \
  --ks-pass pass:kfb123456 --key-pass pass:kfb123456 --ks-key-alias kfb \
  --out "$OUT_APK" $BUILD/app.aligned.apk

echo "==> [8/8] verify"
$BT/apksigner verify --print-certs "$OUT_APK" | head -4
ls -la "$OUT_APK"
echo "DONE: $OUT_APK"
