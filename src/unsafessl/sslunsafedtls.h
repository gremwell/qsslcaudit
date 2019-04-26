/****************************************************************************
**
** Copyright (C) 2018 The Qt Company Ltd.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the QtNetwork module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 3 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL3 included in the
** packaging of this file. Please review the following information to
** ensure the GNU Lesser General Public License version 3 requirements
** will be met: https://www.gnu.org/licenses/lgpl-3.0.html.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 2.0 or (at your option) the GNU General
** Public license version 3 or any later version approved by the KDE Free
** Qt Foundation. The licenses are as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL2 and LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-2.0.html and
** https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/

#ifndef SSLUNSAFEDTLS_H
#define SSLUNSAFEDTLS_H

#include "sslunsafenetworkglobal.h"

#include "sslunsafesocket.h"
#include "sslunsafe.h"

#include <QtCore/qcryptographichash.h>
#include <QtCore/qobject.h>

QT_REQUIRE_CONFIG(dtls);

QT_BEGIN_NAMESPACE

enum class SslUnsafeDtlsError : unsigned char
{
    NoError,
    InvalidInputParameters,
    InvalidOperation,
    UnderlyingSocketError,
    RemoteClosedConnectionError,
    PeerVerificationError,
    TlsInitializationError,
    TlsFatalError,
    TlsNonFatalError
};

class QHostAddress;
class QUdpSocket;
class QByteArray;
class QString;

class SslUnsafeDtlsClientVerifierPrivate;
class SslUnsafeDtlsClientVerifier : public QObject
{
    Q_OBJECT

public:

    explicit SslUnsafeDtlsClientVerifier(QObject *parent = nullptr);
    ~SslUnsafeDtlsClientVerifier();

    struct Q_NETWORK_EXPORT GeneratorParameters
    {
        GeneratorParameters();
        GeneratorParameters(QCryptographicHash::Algorithm a, const QByteArray &s);
        QCryptographicHash::Algorithm hash = QCryptographicHash::Sha1;
        QByteArray secret;
    };

    bool setCookieGeneratorParameters(const GeneratorParameters &params);
    GeneratorParameters cookieGeneratorParameters() const;

    bool verifyClient(QUdpSocket *socket, const QByteArray &dgram,
                      const QHostAddress &address, quint16 port);
    QByteArray verifiedHello() const;

    SslUnsafeDtlsError dtlsError() const;
    QString dtlsErrorString() const;

private:
    QScopedPointer<SslUnsafeDtlsClientVerifierPrivate> d_ptr;

    Q_DECLARE_PRIVATE(SslUnsafeDtlsClientVerifier)
    Q_DISABLE_COPY(SslUnsafeDtlsClientVerifier)
};

class SslUnsafePreSharedKeyAuthenticator;
template<class> class QVector;
class SslUnsafeConfiguration;
class SslUnsafeCipher;
class SslUnsafeError;

class SslUnsafeDtlsPrivate;
class SslUnsafeDtls : public QObject
{
    Q_OBJECT

public:

    enum HandshakeState
    {
        HandshakeNotStarted,
        HandshakeInProgress,
        PeerVerificationFailed,
        HandshakeComplete
    };

    explicit SslUnsafeDtls(SslUnsafeSocket::SslMode mode, QObject *parent = nullptr);
    ~SslUnsafeDtls();

    bool setPeer(const QHostAddress &address, quint16 port,
                 const QString &verificationName = {});
    bool setPeerVerificationName(const QString &name);
    QHostAddress peerAddress() const;
    quint16 peerPort() const;
    QString peerVerificationName() const;
    SslUnsafeSocket::SslMode sslMode() const;

    void setMtuHint(quint16 mtuHint);
    quint16 mtuHint() const;

    using GeneratorParameters = SslUnsafeDtlsClientVerifier::GeneratorParameters;
    bool setCookieGeneratorParameters(const GeneratorParameters &params);
    GeneratorParameters cookieGeneratorParameters() const;

    bool setDtlsConfiguration(const SslUnsafeConfiguration &configuration);
    SslUnsafeConfiguration dtlsConfiguration() const;

    HandshakeState handshakeState() const;

    bool doHandshake(QUdpSocket *socket, const QByteArray &dgram = {});
    bool handleTimeout(QUdpSocket *socket);
    bool resumeHandshake(QUdpSocket *socket);
    bool abortHandshake(QUdpSocket *socket);
    bool shutdown(QUdpSocket *socket);

    bool isConnectionEncrypted() const;
    SslUnsafeCipher sessionCipher() const;
    SslUnsafe::SslProtocol sessionProtocol() const;

    qint64 writeDatagramEncrypted(QUdpSocket *socket, const QByteArray &dgram);
    QByteArray decryptDatagram(QUdpSocket *socket, const QByteArray &dgram);

    SslUnsafeDtlsError dtlsError() const;
    QString dtlsErrorString() const;

    QVector<SslUnsafeError> peerVerificationErrors() const;
    void ignoreVerificationErrors(const QVector<SslUnsafeError> &errorsToIgnore);

Q_SIGNALS:

    void pskRequired(SslUnsafePreSharedKeyAuthenticator *authenticator);
    void handshakeTimeout();

private:
    QScopedPointer<SslUnsafeDtlsPrivate> d_ptr;

    bool startHandshake(QUdpSocket *socket, const QByteArray &dgram);
    bool continueHandshake(QUdpSocket *socket, const QByteArray &dgram);

    Q_DECLARE_PRIVATE(SslUnsafeDtls)
    Q_DISABLE_COPY(SslUnsafeDtls)
};

QT_END_NAMESPACE

#endif // SSLUNSAFEDTLS_H
