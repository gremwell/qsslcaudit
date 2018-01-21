#!/bin/bash

# this script downloads and compiles openssl.
# the resulting libraries and openssl binary are stored in the current directory.
# build is performed in a temporary directory which is removed afterwards.
#
# depending on your operating system you will probably be needed to update
# 'openssldir' variable.

openssldir="/etc/openssl"

opensslver="1.0.2"
opensslrel="i"
name="openssl-${opensslver}${opensslrel}"
archive="$name.tar.gz"

url="https://www.openssl.org/source/old/$opensslver/$archive"

builddir=`mktemp -d`

curdir=`pwd`

pushd $builddir

curl -O $url
if [ $? -ne 0 ]; then
    rm -rf $builddir
    exit
fi

tar -xzf $archive

pushd $name

./config enable-ssl2 enable-weak-ssl-ciphers enable-shared --prefix=/usr --openssldir=$openssldir
make depend
make

cp -a libcrypto.so{,.1.0.0} $curdir
cp -a libssl.so{,.1.0.0} $curdir
cp -a apps/openssl $curdir

popd
popd

rm -rf $builddir
