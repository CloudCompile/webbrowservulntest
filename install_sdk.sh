#!/bin/bash
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export ANDROID_HOME=$PWD/android-sdk
export PATH=$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH
yes | sdkmanager --install "platform-tools" "emulator" "system-images;android-33;google_apis;x86_64" "build-tools;33.0.0" 2>&1
echo "SDK_INSTALL_DONE"
