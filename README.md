# Summary

This tool can be used to determine if an application that uses TLS/SSL for its data transfers does this in a secure way.

`qsslcaudit` was inspired by [sslcaudit](https://github.com/grwl/sslcaudit.git) and performs the same set of tests. However, this tool has been rewritten from scratch using C++ with Qt (that is why there is *q* in the name) instead of Python.

Basically, after performing tests using `qsslcaudit` one can answer the following questions about TLS/SSL client:

* Does it properly verify server's certificate?
* Does it verify that server name (CN) field in the certificate is the same as the target name?
* Does it verify that certificate was issued by an authority that can be trusted?
* Does it support weak protocols (SSLv2, SSLv3) or weak ciphers (EXPORT/LOW/MEDIUM grade)?

If the tested application has some weaknesses in TLS/SSL implementation, there is a risk of man-in-the-middle attack which could lead to sensitive information (such as user credentials) disclosure.

# Installation

## Note on OpenSSL 1.1.0

OpenSSL 1.1.0 removed support for SSLv2 protocol, see https://www.openssl.org/news/changelog.html#x9

Thus, compiling `qsslcaudit` with this version results in some (SSLv2-related) tests not working.

Moreover, runtime linking with "unsafe" library version 1.0.yx with `qsslcaudit` compiled with OpenSSL 1.1.0x is not possible, as these versions are not binary compatible.

For these reasons we advise you to compile `qsslcaudit` using OpenSSL versions 1.0.yx.

## Build Instructions

At the time of writing there was no packages ready for popular Linux distributions. However, compilation from sources should be quite straightforward for engineer that wants to test TLS/SSL client.

Some packages have to be installed in order to compile `qsslcaudit`:

* [Qt](https://www.qt.io/) (Qt5-base) development package
* [GNU TLS](https://www.gnutls.org/) library development package
* [OpenSSL](https://www.openssl.org/) library development package
* [CMake](https://cmake.org/) tool

Packages for ALT Linux (P8, Sisyphus@01-2018): `cmake qt5-base-devel libgnutls-devel libssl-devel`.

Packages for Ubuntu 16.04: `cmake qtbase5-dev libgnutls-dev libssl-dev`.

Packages for Fedora 26: `cmake qt5-qtbase-devel gnutls-devel compat-openssl10-devel`. Probably, you will need to explicitly remove `openssl-devel`.

Packages for Kali (rolling@01-2018): `cmake qtbase5-dev libgnutls28-dev libssl1.0-dev`. Probably, you will need to explicitly remove `libssl-dev`.

Once you have `qsslcaudit` source code repository and packages installed, do the following:

* Create build directory
* Create Makefile (run cmake) there
* Compile sources (run make)
* Install binaries (run make install), optional

```
mkdir build
cd build
cmake ..
make
sudo make install
```

The following binaries will be installed:

* `qsslcaudit.bin` -- main application binary
* `qsslcaudit` -- shell script, which launches `qsslcaudit.bin` with `LD_LIBRARY_PATH` environment variable set to the current directory

Now the tool is ready to use. However, unsafe SSL protocols can be tested only with unsafe OpenSSL library. To have such unsafe version, do the following:

* Create directory where you would like to store unsafe OpenSSL libraries and binary (can be somewhere in your `$HOME`)
* Launch helper script to download and compile unsafe OpenSSL library

```
mkdir openssl
cd openssl
~/Downloads/qsslcaudit/tools/build_openssl.sh
```

That is all. Now, if you want to use `qsslcaudit` with unsafe OpenSSL version, just launch it inside `openssl` directory (or any other you chose).

# Usage

Use `-h` flag to get some usage help.

```
$ qsslcaudit -h
Usage: qsslcaudit.bin [options]
A tool to test SSL clients behavior

SSL client tests:
        1: certificate trust test with user-supplied certificate
        2: certificate trust test with self-signed certificate for user-supplied common name
        3: certificate trust test with self-signed certificate for www.example.com
        4: certificate trust test with user-supplied common name signed by user-supplied certificate
        5: certificate trust test with www.example.com common name signed by user-supplied certificate
        6: certificate trust test with user-supplied common name signed by user-supplied CA certificate
        7: certificate trust test with www.example.com common name signed by user-supplied CA certificate
        8: SSLv2 protocol support test
        9: SSLv3 protocol support test
        10: SSLv3 protocol and EXPORT grade ciphers support test
        11: SSLv3 protocol and LOW grade ciphers support test
        12: SSLv3 protocol and MEDIUM grade ciphers support test


Options:
  -h, --help                      Displays this help.
  -v, --version                   Displays version information.
  -l, --listen-address <0.0.0.0>  listen on <address>
  -p, --listen-port <8443>        bind to <port>
  --user-cn <example.com>         common name (CN) to suggest to client
  --server <https://example.com>  grab certificate information from <server>
  --user-cert <~/host.cert>       path to file containing custom certificate
                                  (or chain of certificates)
  --user-key <~/host.key>         path to file containing custom private key
  --user-ca-cert <~/ca.cert>      path to file containing custom certificate
                                  usable as CA
  --user-ca-key <~/ca.key>        path to file containing custom private key
                                  for CA certificate
  --selected-tests <1,3,5>        comma-separated list of tests (id) to execute
  --forward <127.0.0.1:6666>      forward connection to upstream proxy
  --show-ciphers                  show ciphers provided by loaded openssl
                                  library
```

Usage example:

```
$ qsslcaudit --user-cert ~/example.com_cert+chain.pem --user-key ~/example.com.key --selected-tests 1 
preparing selected tests...

SSL library used: OpenSSL 1.0.2i  22 Sep 2016

running test: certificate trust test with user-supplied certificate
listening on 127.0.0.1:8443
connection from: 127.0.0.1:33808
SSL connection established
received data: GET / HTTP/1.1
Host: 127.0.0.1:8443
User-Agent: curl/7.57.0-DEV
Accept: */*


disconnected
report:
test failed, client accepted fake certificate, data was intercepted
test finished
```

`curl` with `-k` switch was used to trigger certificate verification test failure:

```
$ curl -ik https://127.0.0.1:8443/
curl: (52) Empty reply from server
```

## (Some) Command Line Options

Please note that some options are ignored in certain tests or are essential to others. The application tries to perform all (selected) tests and if the test can not be performed with provided options, it is skipped.

`--selected-tests` selects tests to execute. By default, all tests are performed.

`--forward` in case TLS/SSL connection successfully established (usually this means that MitM attack is possible), forward connection (*non-SSL*) to the specified host:port. This can be used to intercept client-provided data (i.e. credentials in POST requests).

`--starttls` prior initiating TLS/SSL connection the tool performs specified "START TLS" sequence (supported protocols are displayed in help message).

`--show-ciphers` shows ciphers provided by loaded OpenSSL library. This is useful to check which version (official or custom) of OpenSSL is used.

`--user-cn` this option value will be used as CN (common name, server name) value of the certificate, presented to client.

`--server` with this option the tool tries to fetch certificate settings from the user-supplied hostname and present them to client.

`--user-cert`, `--user-key` using this options one can provide specific certificate to present to client.

`--user-ca-cert`, `--user-ca-key` sets path to CA (certificate authority) files to sign certificates presented to client.

## Tests

Current list of TLS/SSL client tests.

### certificate trust test with user-supplied certificate

The client is presented with user-supplied certificate. This is only useful when user-supplied certificate is valid. In case CN differs from the one the client connects to, the connection should not be established. This test verifies that client properly checks for common-name value.

### certificate trust test with self-signed certificate for user-supplied common name

The client is presented with self-signed certificate with common-name taken from user `--user-cn` or `--server` options. This test verifies that client properly checks certificate signer.

### certificate trust test with self-signed certificate for www.example.com

The client is presented with self-signed certificate with common-name set to `www.example.com`. If client connects to such server, then it does not validate neither certificate, nor server name.

### certificate trust test with user-supplied common name signed by user-supplied certificate

The client is presented with certificate signed by user-supplied one with common-name taken from user `--user-cn` or `--server` options. This is only useful when user-supplied certificate is valid (but issued to another domain). This test verifies that client properly checks certificate signer.

### certificate trust test with www.example.com common name signed by user-supplied certificate

The client is presented with certificate signed by user-supplied one but with common-name set to `www.example.com`. This is only useful when user-supplied certificate is valid. If client connects to such server, then it does not validate neither certificate, nor server name.

### certificate trust test with user-supplied common name signed by user-supplied CA certificate

This test simulates situation when CA (certificate authority) keys are stolen.

### certificate trust test with www.example.com common name signed by user-supplied CA certificate

This test simulates situation when CA (certificate authority) keys are stolen.

### SSLv2 protocol support test

The client is presented with self-signed certificate with CN set via `--user-cn` or `--server` options or `www.example.com`. Protocol forced to SSLv2. Client should refuse to connect to such server.

### SSLv3 protocol support test

The client is presented with self-signed certificate with CN set via `--user-cn` or `--server` options or `www.example.com`. Protocol forced to SSLv3. Client should refuse to connect to such server.

### SSLv3 protocol and EXPORT grade ciphers support test

The client is presented with self-signed certificate with CN set via `--user-cn` or `--server` options or `www.example.com`. Protocol forced to SSLv3 and EXPORT-grade ciphers. Client should refuse to connect to such server.

### SSLv3 protocol and LOW grade ciphers support test

The client is presented with self-signed certificate with CN set via `--user-cn` or `--server` options or `www.example.com`. Protocol forced to SSLv3 and LOW-grade ciphers. Client should refuse to connect to such server.

### SSLv3 protocol and MEDIUM grade ciphers support test

The client is presented with self-signed certificate with CN set via `--user-cn` or `--server` options or `www.example.com`. Protocol forced to SSLv3 and MEDIUM-grade ciphers. Client should refuse to connect to such server.

# Adding New Tests

At the time of writing adding new tests requires some knowledge of C++ and QtSsl module API (see http://doc.qt.io/qt-5/ssl.html). However, it should be quite easy to add a new test once the content of `src/ssltest.{h,cpp}` and `src/ssltests.{h,cpp}` is clear.

# Technical Details

`qsslcaudit` is written in C++ and uses [Qt](https://www.qt.io/) library for most of the high-level functions.

The repository includes copy *modified* sources of [Qt Certificate Addon](https://github.com/richmoore/qt-certificate-addon) project. `Qt Certificate Addon` implements abstraction layer over [GNU TLS](https://www.gnutls.org/) library and provides Qt-friendly methods to generate certificates. As its sources were modified (mostly, adaptations to modified Qt SSL stack), it was decided to this project into the repository. However, in future, this decision could be reconsidered.

The most time-consuming part of `qsslcaudit` project development was supporting insecure/unsafe TLS/SSL configurations. Indeed, in present (year 2018) times most operating systems (Linux distributions) include [OpenSSL](https://www.openssl.org/) library compiled with security-safe settings (disabling SSLv2 and weak ciphers). Some TLS/SSL libraries (like GNU TLS) do not support weak protocols at all. Additionally, abstraction layers (QtSsl, Python M2Crypto and others) implement some security checks disabling unsafe configurations. To overcome these problems and be able to test unsafe TLS/SSL cases it was decided to take QtSsl module implementation and make it *unsafe*.

For this reason one can find `src/unsafessl` directory here with QtSsl modules sources taken from https://github.com/qt/qtbase.git, Git tag `v5.9.3`. Obviously, these sources were heavily modified to make them work outside of the Qt main source tree. However, having such complete implementation in our hands is very helpful if we want to test some non-standard cases.
