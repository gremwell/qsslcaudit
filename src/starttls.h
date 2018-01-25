#ifndef STARTTLS_H
#define STARTTLS_H


#ifdef UNSAFE
#define XSslSocket SslUnsafeSocket
#else
#define XSslSocket QSslSocket
#endif

class XSslSocket;

void handleStartTlsFtp(XSslSocket *const socket);

void handleStartTlsSmtp(XSslSocket *const socket);

#endif
