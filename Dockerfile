FROM ubuntu:rolling

RUN apt-get update && apt-get install -y wget

# install SSLv2-enabled version of OpenSSL libraries in a separate location (this does not compromise normal application relying on OpenSSL)
RUN wget https://github.com/gremwell/unsafeopenssl-pkg-debian/releases/download/1.0.2i-2/libunsafessl1.0.2_1.0.2i-2_amd64.deb
RUN wget https://github.com/gremwell/unsafeopenssl-pkg-debian/releases/download/1.0.2i-2/openssl-unsafe_1.0.2i-2_amd64.deb
RUN dpkg -i libunsafessl1.0.2_1.0.2i-2_amd64.deb openssl-unsafe_1.0.2i-2_amd64.deb

# install qsslcaudit and its dependencies
RUN wget https://github.com/gremwell/qsslcaudit/releases/download/v0.2.0/qsslcaudit_0.2.0-1_amd64.deb
RUN apt-get install -y ./qsslcaudit_0.2.0-1_amd64.deb
