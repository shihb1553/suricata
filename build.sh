#!/bin/bash

export CFLAGS="-g -O0 -Wall -Wextra -Werror -Wshadow -Wno-unused-parameter -Wno-unused-function"
export LDFLAGS=""
export BUILD="--enable-unix-socket --enable-luajit"

./script/bundle.sh

bash autogen.sh

./configure --prefix=/home/shihb/Studio/run $BUILD CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS"

make -j4

# make install-full
# make install-conf
# make install-rules
# make install-headers
# make install-library
make install
