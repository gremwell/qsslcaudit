#ifndef TLSHELLO_H
#define TLSHELLO_H

class QByteArray;

bool is_sslv2_clienthello(const QByteArray &packet);
bool is_sslv3_or_tls(const QByteArray &packet);
bool is_sslv3_or_tls_hello(const QByteArray &packet);

#endif
