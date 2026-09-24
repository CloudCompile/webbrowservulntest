#!/bin/bash
#
# Install the Android static-analysis toolchain used by webrecon.
#
# This does NOT install the Android emulator: the emulator needs /dev/kvm, which
# is not exposed in this container. Everything here is pure static analysis and
# needs only the JDK.
#
set -u

export JAVA_HOME=${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}
export PATH="$JAVA_HOME/bin:$PATH"

echo "== installing packages =="
sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    openjdk-21-jdk-headless apktool aapt zipalign unzip curl wget

echo "== installing jadx =="
JADX_VERSION=1.5.6
if ! command -v jadx >/dev/null 2>&1; then
    curl -sSL -o /tmp/jadx.zip \
        "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
    sudo mkdir -p /opt/jadx
    sudo unzip -q -o /tmp/jadx.zip -d /opt/jadx
    sudo chmod +x /opt/jadx/bin/jadx /opt/jadx/bin/jadx-gui
    sudo ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
    sudo ln -sf /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui
fi

echo "== installing python tooling =="
pip3 install --quiet -r "$(dirname "$0")/requirements.txt"

echo
echo "toolchain ready:"
java -version 2>&1 | head -1
apktool --version
jadx --version
python3 -c "import androguard; print('androguard', androguard.__version__)"

# --- optional: emulator (requires /dev/kvm) --------------------------------
# If this host exposes KVM, you can add the emulator + a system image for
# dynamic confirmation of findings:
#
#   export ANDROID_HOME=$PWD/android-sdk
#   export PATH=$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH
#   yes | sdkmanager --install "platform-tools" "emulator" \
#       "system-images;android-33;google_apis;x86_64" "build-tools;33.0.0"
#
echo "SDK_INSTALL_DONE"
