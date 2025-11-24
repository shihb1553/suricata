#!/bin/bash

# ./scripts/bundle.sh

# bash autogen.sh

CFLAGS="-g -O0 -Wall -Wextra -Werror -Wshadow -Wno-unused-parameter -Wno-unused-function"
# CFLAGS+=" -fsanitize=address -fno-omit-frame-pointer -fsanitize-recover=address"

LDFLAGS=""
# detect keyword export function
# LDFLAGS+=" -Wl,--undefined=SCDetectHelperKeywordRegister"
# LDFLAGS+=" -Wl,--undefined=SCDetectHelperBufferRegister"
# LDFLAGS+=" -Wl,--undefined=SCDetectHelperBufferMpmRegister"
# LDS
# LDFLAGS+=" -Wl,--version-script=$TOPDIR/export_symbols.lds"
# LDFLAGS+=" -Wl,-T,$TOPDIR/undef_symbols.lds

BUILD="--enable-unix-socket --enable-luajit"
# BUILD+=" --enable-debug --enable-debug-validation --enable-profiling"
# BUILD+=" --enable-unittests"
# BUILD+=" --enable-ebpf --enable-ebpf-build --with-clang=/usr/bin/clang"

./configure --prefix=/home/shihb/Studio/run $BUILD CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS"

make -j4

# make install-full
# make install-conf
# make install-rules
# make install-headers
# make install-library
make install

# run
# export ASAN_OPTIONS=halt_on_error=0:use_sigaltstack=0:detect_leaks=1:log_path=/tmp/asan.log
# ./bin/suricata --list-keywords=csv (' '/all/csv/dsize)
# LD_LIBRARY_PATH=./lib ./bin/suricata -c etc/suricata/suricata.yaml --simulate-ips -k none -i eth0
# LD_LIBRARY_PATH=./lib ./bin/suricata -c ./etc/suricata/suricata.yaml --fatal-unittests -u -l .
# LD_LIBRARY_PATH=./lib ./bin/suricata -c ./etc/suricata/suricata.yaml -u -U DetectTransformZipParseTest01
# LD_LIBRARY_PATH=./lib ./bin/suricata -c etc/suricata/suricata.yaml --simulate-ips -k none --af-xdp=enp3s0
# LD_LIBRARY_PATH=./lib ./bin/suricata -c etc/suricata/suricata.yaml --simulate-ips -k none -r pcaps/
