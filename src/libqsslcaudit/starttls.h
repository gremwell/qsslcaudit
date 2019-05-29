#ifndef STARTTLS_H
#define STARTTLS_H


class XSslSocket;

void handleStartTlsFtp(XSslSocket *const socket);

void handleStartTlsSmtp(XSslSocket *const socket);

void handleStartTlsXmpp(XSslSocket *const socket);

#endif
