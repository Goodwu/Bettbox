#!/usr/bin/env bash
set -euo pipefail
mkdir -p api24-test-results
APK="build/app/outputs/flutter-apk/app-x86_64-release.apk"
PACKAGE="com.appshub.bettbox"
test -s "$APK"
adb wait-for-device
adb shell getprop ro.build.version.sdk | tee api24-test-results/device-sdk.txt
test "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" = "24"
adb install -r "$APK" | tee api24-test-results/install.txt
adb logcat -c
adb shell am force-stop "$PACKAGE" || true
adb shell am start -W -n "$PACKAGE/.MainActivity" | tee api24-test-results/launch.txt
sleep 25
adb shell pidof "$PACKAGE" | tee api24-test-results/pid.txt
adb shell dumpsys activity activities > api24-test-results/activities.txt
adb logcat -d -v threadtime > api24-test-results/logcat.txt
if grep -E "FATAL EXCEPTION|NoSuchMethodError|NoClassDefFoundError|UnsatisfiedLinkError" api24-test-results/logcat.txt | grep -E -A 0 "$PACKAGE|AndroidRuntime|com.appshub" > api24-test-results/suspected-crashes.txt; then
  echo "::error::Detected possible compatibility crash"
  cat api24-test-results/suspected-crashes.txt
  exit 1
fi
echo "API 24 APK installed and process survived cold start"
