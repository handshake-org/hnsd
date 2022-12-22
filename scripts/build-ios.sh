#! /bin/sh
# based on libsodium build script
export PREFIX="$(pwd)/hsk-apple"

export IOS64_PREFIX="${PREFIX}/tmp/ios64"
export IOS_SIMULATOR_ARM64_PREFIX="${PREFIX}/tmp/ios-simulator-arm64"
export IOS_SIMULATOR_X86_64_PREFIX="${PREFIX}/tmp/ios-simulator-x86_64"

export LOG_FILE="${PREFIX}/tmp/build_log"
export XCODEDIR="$(xcode-select -p)"

export IOS_SIMULATOR_VERSION_MIN=${IOS_SIMULATOR_VERSION_MIN-"9.0.0"}
export IOS_VERSION_MIN=${IOS_VERSION_MIN-"9.0.0"}

NPROCESSORS=$(getconf NPROCESSORS_ONLN 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null)
PROCESSORS=${NPROCESSORS:-3}

build_ios() {
  export BASEDIR="${XCODEDIR}/Platforms/iPhoneOS.platform/Developer"
  export PATH="${BASEDIR}/usr/bin:$BASEDIR/usr/sbin:$PATH"
  export SDK="${BASEDIR}/SDKs/iPhoneOS.sdk"

  ## 64-bit iOS
  export CFLAGS="-fembed-bitcode -O2 -arch arm64 -isysroot ${SDK} -mios-version-min=${IOS_VERSION_MIN}"
  export LDFLAGS="-fembed-bitcode -arch arm64 -isysroot ${SDK} -mios-version-min=${IOS_VERSION_MIN}"

  make clean >/dev/null 2>&1
  ./configure --without-daemon --host=arm-apple-darwin10 --prefix="$IOS64_PREFIX"
  make -j${PROCESSORS} install || exit 1
}

build_ios_simulator() {
  export BASEDIR="${XCODEDIR}/Platforms/iPhoneSimulator.platform/Developer"
  export PATH="${BASEDIR}/usr/bin:$BASEDIR/usr/sbin:$PATH"
  export SDK="${BASEDIR}/SDKs/iPhoneSimulator.sdk"

  ## arm64 simulator
  export CFLAGS="-fembed-bitcode -O2 -arch arm64 -isysroot ${SDK} -mios-simulator-version-min=${IOS_SIMULATOR_VERSION_MIN}"
  export LDFLAGS="-fembed-bitcode -arch arm64 -isysroot ${SDK} -mios-simulator-version-min=${IOS_SIMULATOR_VERSION_MIN}"

  make clean >/dev/null 2>&1
  ./configure --without-daemon --host=arm-apple-darwin20 --prefix="$IOS_SIMULATOR_ARM64_PREFIX"
  make -j${PROCESSORS} install || exit 1

  ## x86_64 simulator
  export CFLAGS="-fembed-bitcode -O2 -arch x86_64 -isysroot ${SDK} -mios-simulator-version-min=${IOS_SIMULATOR_VERSION_MIN}"
  export LDFLAGS="-fembed-bitcode -arch x86_64 -isysroot ${SDK} -mios-simulator-version-min=${IOS_SIMULATOR_VERSION_MIN}"

  make clean >/dev/null 2>&1
  ./configure --without-daemon --host=x86_64-apple-darwin10 --prefix="${IOS_SIMULATOR_X86_64_PREFIX}"
  make -j"${PROCESSORS}" install || exit 1
}


mkdir -p "${PREFIX}/tmp"


if [ "$1" = "ios" ]; then

    echo "Building for iOS..."
    build_ios
    mkdir -p "${PREFIX}/ios/lib"
    cp -a "${IOS64_PREFIX}/include" "${PREFIX}/ios/"
    cp "$IOS64_PREFIX/lib/libhsk.a" "$PREFIX/ios/lib/libhsk.a"
    cp "$IOS64_PREFIX/lib/libuv.a" "$PREFIX/ios/lib/libuv.a"

elif [ "$1" = "iossimulator" ]; then

    echo "Building for iOS Simulator..."
    build_ios_simulator
    mkdir -p "${PREFIX}/ios/lib"
    cp -a "${IOS_SIMULATOR_X86_64_PREFIX}/include" "${PREFIX}/ios/"
    cp "$IOS_SIMULATOR_X86_64_PREFIX/lib/libhsk.a" "$PREFIX/ios/lib/libhsk.a"
    cp "$IOS_SIMULATOR_X86_64_PREFIX/lib/libuv.a" "$PREFIX/ios/lib/libuv.a"
fi


if [ "$2" = "-o" ]; then
    cp -a -f "${PREFIX}/ios/" $3
fi
