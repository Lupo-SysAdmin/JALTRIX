#!/bin/sh
# Build a private development engine. Requires compiler/CMake/Ninja and Snort's development dependencies.
set -eu
cd "$(dirname "$0")/.."
project_root="$PWD"
prefix="$project_root/.runtime/snort-3.13.2.0"
mkdir -p .runtime/sources
curl -fL --retry 2 https://github.com/snort3/snort3/archive/refs/tags/3.13.2.0.tar.gz -o .runtime/sources/snort3-3.13.2.0.tar.gz
curl -fL --retry 2 https://github.com/snort3/libdaq/archive/refs/tags/v3.0.29.tar.gz -o .runtime/sources/libdaq-3.0.29.tar.gz
sha256sum -c <<'SUMS'
298367524a31f0d4725ef12b2b06265b4e76e6545f990ae3dc3b5e4c10f6e0ea  .runtime/sources/snort3-3.13.2.0.tar.gz
136deba78d195163687eb71a6dc81b725c27fde7765b7ef70eb741c371e887a8  .runtime/sources/libdaq-3.0.29.tar.gz
SUMS
tar -xzf .runtime/sources/libdaq-3.0.29.tar.gz -C .runtime/sources
tar -xzf .runtime/sources/snort3-3.13.2.0.tar.gz -C .runtime/sources
(
    cd .runtime/sources/libdaq-3.0.29
    ./bootstrap
    ./configure --prefix="$prefix"
    make -j"${SNORT_BUILD_JOBS:-6}"
    make install
)
for patch_file in packaging/patches/*.patch; do
    patch -d .runtime/sources/snort3-3.13.2.0 -p1 < "$patch_file"
done
PKG_CONFIG_PATH="$prefix/lib/pkgconfig" cmake -S .runtime/sources/snort3-3.13.2.0 -B .runtime/build-snort -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix" \
    '-DCMAKE_INSTALL_RPATH=$ORIGIN/../lib' -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build .runtime/build-snort -j"${SNORT_BUILD_JOBS:-6}"
cmake --install .runtime/build-snort
"$prefix/bin/snort" -V
