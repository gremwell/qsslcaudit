[![Build Status](https://travis-ci.com/gremwell/qsslcaudit.svg?branch=master)](https://travis-ci.com/gremwell/qsslcaudit)

<!-- markdown-toc start - Don't edit this section. Run M-x markdown-toc-refresh-toc -->
**Table of Contents**

- [Summary](#summary)
- [Installation from Binary Packages](#installation-from-binary-packages)
    - [Debian / Kali](#debian--kali)
    - [ALTLinux](#altlinux)
- [Installation from Sources](#installation-from-sources)
    - [Note on OpenSSL 1.1.0](#note-on-openssl-110)
    - [Note on unsafe OpenSSL variant](#note-on-unsafe-openssl-variant)
    - [Build Instructions](#build-instructions)
        - [Detailed build description](#detailed-build-description)
            - [Building unsafe OpenSSL library](#building-unsafe-openssl-library)
- [Usage](#usage)
    - [Forwarding Connection](#forwarding-connection)
        - [application settings](#application-settings)
        - [hosts file](#hosts-file)
        - [traffic forwarding](#traffic-forwarding)
        - [using proxy](#using-proxy)
    - [Usage Example #1](#usage-example-1)
    - [Usage Example #2](#usage-example-2)
    - [Usage Example #3](#usage-example-3)
    - [(Some) Command Line Options](#some-command-line-options)
    - [Tests](#tests)
        - [certificate trust test with user-supplied certificate](#certificate-trust-test-with-user-supplied-certificate)
        - [certificate trust test with self-signed certificate for user-supplied common name](#certificate-trust-test-with-self-signed-certificate-for-user-supplied-common-name)
        - [certificate trust test with self-signed certificate for www.example.com](#certificate-trust-test-with-self-signed-certificate-for-wwwexamplecom)
        - [certificate trust test with user-supplied common name signed by user-supplied certificate](#certificate-trust-test-with-user-supplied-common-name-signed-by-user-supplied-certificate)
        - [certificate trust test with www.example.com common name signed by user-supplied certificate](#certificate-trust-test-with-wwwexamplecom-common-name-signed-by-user-supplied-certificate)
        - [certificate trust test with user-supplied common name signed by user-supplied CA certificate](#certificate-trust-test-with-user-supplied-common-name-signed-by-user-supplied-ca-certificate)
        - [certificate trust test with www.example.com common name signed by user-supplied CA certificate](#certificate-trust-test-with-wwwexamplecom-common-name-signed-by-user-supplied-ca-certificate)
        - [SSLv2 protocol support test](#sslv2-protocol-support-test)
        - [SSLv3 protocol support test](#sslv3-protocol-support-test)
        - [SSLv3 protocol and EXPORT grade ciphers support test](#sslv3-protocol-and-export-grade-ciphers-support-test)
        - [SSLv3 protocol and LOW grade ciphers support test](#sslv3-protocol-and-low-grade-ciphers-support-test)
        - [SSLv3 protocol and MEDIUM grade ciphers support test](#sslv3-protocol-and-medium-grade-ciphers-support-test)
- [Adding New Tests](#adding-new-tests)
- [Technical Details](#technical-details)

<!-- markdown-toc end -->
# Summary

This tool can be used to determine if an application that uses TLS/SSL for its data transfers does this in a secure way.

`qsslcaudit` was inspired by [sslcaudit](https://github.com/grwl/sslcaudit.git) and performs the same set of tests. However, this tool has been rewritten from scratch using C++ with Qt (that is why there is *q* in the name) instead of Python.

Basically, after performing tests using `qsslcaudit` one can answer the following questions about TLS/SSL client:

* Does it properly verify a server's certificate?
* Does it verify that server name (CN) field in the certificate is the same as the target name?
* Does it verify that certificate was issued by an authority that can be trusted?
* Does it support weak protocols (SSLv2, SSLv3) or weak ciphers (EXPORT/LOW/MEDIUM grade)?

If the tested application has some weaknesses in TLS/SSL implementation, there is a risk of man-in-the-middle attack which could lead to sensitive information (such as user credentials) disclosure.

Assume that we have mobile application which at some point requests https://login.domain.tld/ Such request can be forwarded to rogue server (i.e. on public WiFi network) and, if mobile app does not verify the server's certificate, users credentials will be intercepted.

To check how the application behaves in this scenario we should setup our own rogue TLS/SSL server and forward the app to it. Then we launch the application, try to login and observe the results. In case login failed -- all is fine.

However, there could be misconfigurations on client which are not easy to find. For instance, the application can check that server's certificate is valid, but does not check if it is issued to the target domain (does not check CN property).

In order to help with tasks like described above, `qsslcaudit` tool has been created.

# Installation from Binary Packages

## Prior note

The tool heavily relies on unsafe version of OpenSSL library (see below). It is separately packaged. Do not that its installation will not interfere with system version of OpenSSL and will not introduce security risks by itself.

`qsslcaudit` uses only unsafe *libraries*. However, you might be interested in `openssl-unsafe` package which can be used to connect to TLS servers using insecure protocols/ciphers. This is can be combined with tools like [testssl.sh](https://testssl.sh).

## Ubuntu

Use PPA to install packages on Xenial and Bionic distros:
```
add-apt-repository ppa:gremwell/qsslcaudit
apt-get update
apt-get install qsslcaudit
```

## Kali

Use the corresponding repository to install packages. Add the following line to your sources list:
```
deb http://pkg.gremwell.com/kali kali main
```

Import Gremwell key used for packaging (fingerprint is `F1ACAA9B4A123E4A897A90AFF91BDF3688550108`):
```
wget -O - http://pkg.gremwell.com/gremwell.asc | apt-key add -
```

Update `apt` cache and install packages:
```
apt-get update
apt-get install qsslcaudit
```

# Installation from Sources

## Note on OpenSSL 1.1.0

OpenSSL 1.1.0 removed support for SSLv2 protocol and other insecure features, see https://www.openssl.org/news/changelog.html#x9

Thus, compiling `qsslcaudit` with this version results in some (i.e. SSLv2-related) tests not working.

Moreover, runtime linking with "unsafe" library version 1.0.yx with `qsslcaudit` compiled with OpenSSL 1.1.0x is not possible, as these versions are not binary compatible.

For these reasons we advise you to compile `qsslcaudit` using OpenSSL versions 1.0.yx.

## Note on unsafe OpenSSL variant

As even 1.0.x versions are too safe for some of the tests included, we prepared so-called *unsafe* build of OpenSSL library. See https://github.com/gremwell/unsafeopenssl-pkg-deb

Packages backed from this repo follow filesystem hierarchy standard but install renamed OpenSSL libraries, i.e. `libunsafessl` and `libunsafecrypto`. This makes it impossible to accidentally link your program against these libraries. Additionally, they provide `openssl-unsafe` binary which can be useful by itself with tools like [testssl.sh](https://testssl.sh/)

Build system of `qsslcaudit` determines which OpenSSL variant is installed and will use *unsafe* version if it is available.

## Build Instructions

Some packages have to be installed in order to compile `qsslcaudit`:

* [Qt](https://www.qt.io/) (Qt5-base) development package
* [GNU TLS](https://www.gnutls.org/) library development package
* [OpenSSL](https://www.openssl.org/) library development package
* [CMake](https://cmake.org/) tool

If you want to use unsafe OpenSSL variant, install corresponding "-dev" packages from PPA/Kali repositories mentioned earlier. This is a recommended way as having `qsslcaudit` in its *safe* form allows to perform very little amount of tests.

Installing packages for Kali: `sudo apt-get install cmake qtbase5-dev libgnutls28-dev libunsafessl-dev`.

Installing packages for Ubuntu 16.04: `sudo apt-get install cmake qtbase5-dev libgnutls-dev libunsafessl-dev`.

Installing packages for Ubuntu 18.04: `sudo apt-get install cmake qtbase5-dev libgnutls28-dev libunsafessl-dev`.

### Detailed build description

Once you have `qsslcaudit` source code repository and packages installed, do the following (inside cloned repo):

* Create build directory
* Create Makefile (run cmake) there
* Compile sources (run make)
* Install binaries (run make install), optional

```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
sudo make install
```

Now the tool is installed.

OpenSSL library is determined during `cmake` run. If your system has the unsafe version (see above), it will be used. Otherwise -- available system version (1.0.x or 1.1.x).

#### Building unsafe OpenSSL library

Manual building unsafe OpenSSL library is (now) not supported. For those who are curious, see spec files in the corresponding `unsafeopenssl` repository.

# Usage

Use `-h` flag to get some usage help.

The most easy way to understand how to use the tool properly is to follow examples provided below.

## Forwarding Connection

The first task before launching any test is to configure forwarding connections from client to `qsslcaudit` instance. This depends on the client itself and network configuration. Thus, there is no common solution. However, several recommendations still can be provided.

### application settings

In some cases the client can be reconfigured to connect to another hostname. I.e.: login.domain.tld --> login.rogue.tld.

Implications:

* If you own SSL certificate for login.rogue.tld and use it in `qsslcaudit` tests, the client will successfully connect to `qsslcaudit` instance. Corresponding test will fail, but technically all is correct. This can be used as MitM configuration for traffic interception.

### hosts file

Modify `hosts` file on the system where client is. Change IP address of the target domain to the IP address of the host running `qsslcaudit`.

Implications:

* superuser privileges required on client's system to edit `hosts` file;
* superuser privileges required on server's system to listen privileged port (443, as we can not change port number via `hosts` file);

### traffic forwarding

The actual setup highly depends on network configuration.

For instance: TLS/SSL client as mobile application running on Android/iOS device. Device is connected to the Internet via laptop's WiFi access point. WiFi network: `192.168.12.0/24`. Use the following commands on laptop's OS:

```
sudo sysctl -w net.ipv4.conf.all.route_localnet=1  # enable forwarding on local interfaces
sudo iptables -t nat -A PREROUTING -p tcp -d login.domain.tld --dport 443 -s 192.168.12.0/24 -j DNAT --to-destination 127.0.0.1:8443  # forward connections to login.domain.tld:443 towards qsslcaudit instance on 127.0.0.1:8443
```

SSH port forwarding can help if `hosts` file was modified on client's system and running `qsslcaudit` as root is not an option:

```
sudo ssh user@127.0.0.1 -L 0.0.0.0:443:127.0.0.1:8443 -N  # forward connections to port 443 from outside towards local listener on port 8443
```

Implications:

* superuser privileges on systems where forwarding is configured;
* difficult to implement and debug in case of problems;

### using proxy

Connections can also be forwarded with help of HTTP proxy:

* Setup HTTP/HTTPS proxy on the host which has network access to `qsslcaudit` instance.
* Configure the client's system to use proxy.
* Configure proxy to forward incoming connections to the target host towards `qsslcaudit` listener. This is complicated step which is described below.

Forwarding connections can not be done in [Burp](http://releases.portswigger.net/) (the only option is to forward all connections). [Fiddler](https://www.telerik.com/fiddler) also does not support such mode. A custom tool can be used (like Python script).

[proxenet](https://github.com/hugsy/proxenet.git) tool has this functionality with adaptation from [forward_http](https://github.com/zOrg1331/proxenet/tree/forward_http) branch. Use it like in the following example:

```
$ proxenet -v -I -m login.domain.tld -N -b 0.0.0.0 -p 8080 -X 127.0.0.1 -P 8443
```

This command forwards incoming connections to login.domain.tld towards proxy at 127.0.0.1:8443 and deals with others as usual.

Implications:

* no out-of-the-box proxy tool with required functionality

## Usage Example #1

Test if client accepts self-signed certificates:

```
$ qsslcaudit --selected-tests 2 --user-cn login.domain.tld
preparing selected tests...

SSL library used: OpenSSL 1.0.2i  22 Sep 2016

running test: certificate trust test with self-signed certificate for user-supplied common name
listening on 127.0.0.1:8443
connection from: 127.0.0.1:36336
ssl error: Error during SSL handshake: error:14094418:SSL routines:ssl3_read_bytes:tlsv1 alert unknown ca (-1)
        The SSL/TLS handshake failed, so the connection was closed.
no data received (Unknown error)
report:
test passed, client refused fake certificate
test finished
```

Test results are OK, client refused to connect to our rogue instance.

Simulate negative result using `curl` with `-k` switch:

```
$ curl -ik https://127.0.0.1:8443/
curl: (52) Empty reply from server
```

We get the following from `qsslcaudit`:

```
$ qsslcaudit --selected-tests 2 --user-cn login.domain.tld
preparing selected tests...

SSL library used: OpenSSL 1.0.2i  22 Sep 2016

running test: certificate trust test with self-signed certificate for user-supplied common name
listening on 127.0.0.1:8443
connection from: 127.0.0.1:36342
SSL connection established
received data: GET / HTTP/1.1
Host: 127.0.0.1:8443
User-Agent: curl/7.58.0-DEV
Accept: */*


disconnected
report:
test failed, client accepted fake certificate, data was intercepted
test finished
```

Even data was intercepted.

## Usage Example #2

Test if client accepts valid certificate for another domain. It is similar to the example above, but we explicitly set which certificate to present to client. Note that full chain of public keys should be included in certificate file.

```
$ qsslcaudit --selected-tests 1 --user-cert ~/untrusted.domain.com_cert+chain.pem --user-key ~/untrusted.domain.com.key -l 0.0.0.0
preparing selected tests...

SSL library used: OpenSSL 1.0.2n  7 Dec 2017

running test: certificate trust test with user-supplied certificate
listening on 0.0.0.0:8443
connection from: 91.XX.XX.90:53976
SSL connection established
ssl error: The TLS/SSL connection has been closed (-1)
ssl error: The remote host closed the connection (-1)
no data received (The remote host closed the connection)
report:
test passed, client refused fake certificate
test finished
```

Test returned OK as we connect to this host using another domain name:

```
$ curl https://trusted.domain.com:8443/
curl: (51) SSL: no alternative certificate subject name matches target host name 'trusted.domain.com'
```

In case the client connects using `untrusted.domain.com` hostname the test fails:

```
$ qsslcaudit --selected-tests 1 --user-cert ~/untrusted.domain.com_cert+chain.pem --user-key ~/untrusted.domain.com.key -l 0.0.0.0
preparing selected tests...

SSL library used: OpenSSL 1.0.2n  7 Dec 2017

running test: certificate trust test with user-supplied certificate
listening on 0.0.0.0:8443
connection from: 91.XX.XX.90:53986
SSL connection established
received data: GET / HTTP/1.1
Host: untrusted.domain.com:8443
User-Agent: curl/7.58.0-DEV
Accept: */*


disconnected
report:
test failed, client accepted fake certificate, data was intercepted
test finished
```

## Usage Example #3

Another possible misconfiguration on client side is support of insecure protocols (SSLv2, SSLv3) and ciphers: EXPORT/LOW/MEDIUM.

This can be tested in the following way:

```
$ qsslcaudit --selected-tests 12
preparing selected tests...

SSL library used: OpenSSL 1.0.2i  22 Sep 2016

running test: test for SSLv3 protocol and MEDIUM grade ciphers support
listening on 127.0.0.1:8443
connection from: 127.0.0.1:38652
SSL connection established
ssl error: Network operation timed out (-1)
no data received (Network operation timed out)
report:
test failed, client accepted fake certificate and weak protocol, but no data transmitted
test finished
```

We simulated test failure by using `s_client` tool with explicitly set weak configuration:

```
$ openssl s_client -connect 127.0.0.1:8443 -ssl3 -cipher MEDIUM
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

`--loop-tests` this is helpful when it is desired to test TLS/SSL client multiple times or launch SSL server assessment tools against `qsslcaudit`.

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

For this reason one can find `src/unsafessl` directory here with QtSsl modules sources taken from https://github.com/qt/qtbase.git, Git tag `v5.10.0`. Obviously, these sources were heavily modified to make them work outside of the Qt main source tree. However, having such complete implementation in our hands is very helpful if we want to test some non-standard cases.
