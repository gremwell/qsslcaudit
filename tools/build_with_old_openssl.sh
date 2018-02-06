#!/bin/bash

# this script downloads and compiles openssl in temporary directory.
# compiled library is then installed to another temporary directory.
#
# after that qsslcaudit (sources path is specified as a parameter) is compiled
# and installed system-wide.

qsslcauditdir="$1"

if [ -z "$1" ] || ! [ -d "$1" ]; then
    echo "provide path to qsslcaudit sources directory as the first argument"
    exit -1
fi

curdir=`pwd`

opensslver="1.0.2"
opensslrel="i"

name="openssl-${opensslver}${opensslrel}"
archive="$name.tar.gz"

url="https://www.openssl.org/source/old/$opensslver/$archive"

builddir=`mktemp -d`
opensslprefix=`mktemp -d`

pushd $builddir

curl -O $url
if [ $? -ne 0 ]; then
    rm -rf $builddir
    exit
fi

tar -xzf $archive

pushd $name

./config enable-ssl2 enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers \
         enable-shared --prefix="${opensslprefix}" --openssldir="${opensslprefix}/etc/ssl"
make depend
make
make install

popd
popd

rm -rf $builddir

# extract libraries we will need in future
pushd $opensslprefix
cp -a lib/libcrypto.so* $curdir
cp -a lib/libssl.so* $curdir
cp -a bin/openssl $curdir
popd

# make all distros happy
ln -sf libssl.so{.1.0.0,.10}
ln -sf libcrypto.so{.1.0.0,.10}
ln -sf libssl.so{.1.0.0,.1.0.2}
ln -sf libcrypto.so{.1.0.0,.1.0.2}

# now, build qsslcaudit using prepared openssl
builddir=`mktemp -d`
pushd $builddir

cmake -DOPENSSL_ROOT_DIR="$opensslprefix" $qsslcauditdir
make
sudo make install
popd

rm -rf $builddir
rm -rf $opensslprefix
