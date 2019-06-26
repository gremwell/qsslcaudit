#ifndef TLSHELLO_H
#define TLSHELLO_H

#include <QByteArray>
#include <QList>

class TlsClientHelloInfo;

bool is_sslv2_clienthello(const QByteArray &packet);
bool is_sslv3_or_tls(const QByteArray &packet);
bool is_sslv3_or_tls_hello(const QByteArray &packet);
void dissect_ssl2_hnd_client_hello(const QByteArray &packet, TlsClientHelloInfo *tlsHelloInfo);
void ssl_dissect_hnd_cli_hello(const QByteArray &packet, TlsClientHelloInfo *tlsHelloInfo);
QString cipherStringFromId(unsigned int id);
bool isUnknownCipher(unsigned int id);
QString extensionCurveStringFromId(unsigned int id);
bool isUnknownExtensionCurve(unsigned int id);

#endif
