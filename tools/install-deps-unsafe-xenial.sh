#!/bin/sh

add-apt-repository ppa:gremwell/qsslcaudit
apt-get update
apt-get install -y libunsafessl-dev openssl-unsafe

apt-get install -y cmake qtbase5-dev libgnutls-dev libcrypto++-dev
