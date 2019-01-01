#!/bin/sh

rm -rf build && mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DWITH_TESTS=true ..
make install
