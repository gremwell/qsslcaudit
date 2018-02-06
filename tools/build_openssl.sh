#!/bin/bash

# this script downloads and compiles openssl.
# the resulting libraries and openssl binary are stored in the current directory.
# build is performed in a temporary directory which is removed afterwards.
#
# to build openssl version 1.1.x, set variable 'useopenssl11' to "yes".
#
# depending on your operating system you will probably be needed to update
# 'openssldir' variable.

openssldir="/etc/openssl"

useopenssl11="no"

opensslver="1.0.2"
opensslrel="i"

if [ $useopenssl11 = "yes" ]; then
    opensslver="1.1.0"
    opensslrel="f"
fi

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

./config enable-ssl2 enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers enable-shared --prefix=/usr --openssldir=$openssldir
make depend
make

if [ $useopenssl11 = "yes" ]; then
    cp -a libcrypto.so{,.1.1} $curdir
    cp -a libssl.so{,.1.1} $curdir
    ln -sf libssl.so{.1.1,.11}
    ln -sf libcrypto.so{.1.1,.11}
else
    cp -a libcrypto.so{,.1.0.0} $curdir
    cp -a libssl.so{,.1.0.0} $curdir
    ln -sf libssl.so{.1.0.0,.10}
    ln -sf libcrypto.so{.1.0.0,.10}
    ln -sf libssl.so{.1.0.0,.1.0.2}
    ln -sf libcrypto.so{.1.0.0,.1.0.2}
fi
cp -a apps/openssl $curdir

popd
popd

rm -rf $builddir
