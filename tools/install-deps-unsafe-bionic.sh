#!/bin/sh

wget https://github.com/gremwell/unsafeopenssl-pkg-debian/releases/download/1.0.2i-2/libunsafessl-dev_1.0.2i-2_ubuntu16.04_amd64.deb
wget https://github.com/gremwell/unsafeopenssl-pkg-debian/releases/download/1.0.2i-2/libunsafessl1.0.2_1.0.2i-2_ubuntu16.04_amd64.deb
wget https://github.com/gremwell/unsafeopenssl-pkg-debian/releases/download/1.0.2i-2/openssl-unsafe_1.0.2i-2_ubuntu16.04_amd64.deb
apt-get install -y ./libunsafessl1.0.2_1.0.2i-2_ubuntu16.04_amd64.deb ./libunsafessl-dev_1.0.2i-2_ubuntu16.04_amd64.deb ./openssl-unsafe_1.0.2i-2_ubuntu16.04_amd64.deb
rm ./libunsafessl1.0.2_1.0.2i-2_ubuntu16.04_amd64.deb ./libunsafessl-dev_1.0.2i-2_ubuntu16.04_amd64.deb ./openssl-unsafe_1.0.2i-2_ubuntu16.04_amd64.deb

apt-get install -y cmake qtbase5-dev g++ libgnutls28-dev
