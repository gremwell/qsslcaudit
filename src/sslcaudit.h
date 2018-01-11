
#ifndef SSLCAUDIT_H
#define SSLCAUDIT_H

#include <QObject>
#include <QAbstractSocket>

#ifdef UNSAFE
#include "sslunsafeerror.h"
#else
#include <QSslError>
#endif

#include "sslusersettings.h"
#include "ssltest.h"

#ifdef UNSAFE
#define XSslSocket SslUnsafeSocket
#define XSslError SslUnsafeError
#define XSslCertificate SslUnsafeCertificate
#else
#define XSslSocket QSslSocket
#define XSslError QSslError
#define XSslCertificate QSslCertificate
#endif


class SslCAudit : public QObject
{
    Q_OBJECT

public:
    SslCAudit(const SslUserSettings settings, QObject *parent = 0);

    void setSslTests(const QList<SslTest *> &tests);

public slots:
    void run();

private slots:
    void handleSocketError(QAbstractSocket::SocketError socketError);
    void handleSslErrors(const QList<XSslError> &errors);
    void handlePeerVerifyError(const XSslError &error);
    void sslHandshakeFinished();

private:
    void runTest(const SslTest *test);

    SslUserSettings settings;
    QList<SslTest *> sslTests;

    QList<XSslError> testSslErrors;
    QList<QAbstractSocket::SocketError> testSocketErrors;
    bool testSslConnectionEstablished;
    bool testDataReceived;

};

#endif // SSLCAUDIT_H
