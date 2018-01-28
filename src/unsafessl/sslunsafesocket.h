/****************************************************************************
**
** Copyright (C) 2016 The Qt Company Ltd.
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


#ifndef SSLUNSAFESOCKET_H
#define SSLUNSAFESOCKET_H

#include "sslunsafenetworkglobal.h"
#include <QtCore/qlist.h>
#include <QtCore/qregexp.h>
#ifndef QT_NO_SSL
#   include <QtNetwork/qtcpsocket.h>
#   include "sslunsafeerror.h"
#endif

QT_BEGIN_NAMESPACE


#ifndef QT_NO_SSL

class QDir;
class SslUnsafeCipher;
class SslUnsafeCertificate;
class SslUnsafeConfiguration;
class SslUnsafeEllipticCurve;
class SslUnsafePreSharedKeyAuthenticator;

class SslUnsafeSocketPrivate;
class SslUnsafeSocketBackendPrivate;
class Q_NETWORK_EXPORT SslUnsafeSocket : public QTcpSocket
{
    Q_OBJECT
public:
    enum SslMode {
        UnencryptedMode,
        SslClientMode,
        SslServerMode
    };

    enum PeerVerifyMode {
        VerifyNone,
        QueryPeer,
        VerifyPeer,
        AutoVerifyPeer
    };

    explicit SslUnsafeSocket(QObject *parent = Q_NULLPTR);
    ~SslUnsafeSocket();
    void resume() Q_DECL_OVERRIDE; // to continue after proxy authentication required, SSL errors etc.

    // Autostarting the SSL client handshake.
    void connectToHostEncrypted(const QString &hostName, quint16 port, OpenMode mode = ReadWrite, NetworkLayerProtocol protocol = AnyIPProtocol);
    void connectToHostEncrypted(const QString &hostName, quint16 port, const QString &sslPeerName, OpenMode mode = ReadWrite, NetworkLayerProtocol protocol = AnyIPProtocol);
    bool setSocketDescriptor(qintptr socketDescriptor, SocketState state = ConnectedState,
                             OpenMode openMode = ReadWrite) Q_DECL_OVERRIDE;

    using QAbstractSocket::connectToHost;
    void connectToHost(const QString &hostName, quint16 port, OpenMode openMode = ReadWrite, NetworkLayerProtocol protocol = AnyIPProtocol) Q_DECL_OVERRIDE;
    void disconnectFromHost() Q_DECL_OVERRIDE;

    virtual void setSocketOption(QAbstractSocket::SocketOption option, const QVariant &value) Q_DECL_OVERRIDE;
    virtual QVariant socketOption(QAbstractSocket::SocketOption option) Q_DECL_OVERRIDE;

    SslMode mode() const;
    bool isEncrypted() const;

    SslUnsafe::SslProtocol protocol() const;
    void setProtocol(SslUnsafe::SslProtocol protocol);

    SslUnsafeSocket::PeerVerifyMode peerVerifyMode() const;
    void setPeerVerifyMode(SslUnsafeSocket::PeerVerifyMode mode);

    int peerVerifyDepth() const;
    void setPeerVerifyDepth(int depth);

    QString peerVerifyName() const;
    void setPeerVerifyName(const QString &hostName);

    // From QIODevice
    qint64 bytesAvailable() const Q_DECL_OVERRIDE;
    qint64 bytesToWrite() const Q_DECL_OVERRIDE;
    bool canReadLine() const Q_DECL_OVERRIDE;
    void close() Q_DECL_OVERRIDE;
    bool atEnd() const Q_DECL_OVERRIDE;
    bool flush(); // ### Qt6: remove me (implementation moved to private flush())
    void abort();

    // From QAbstractSocket:
    void setReadBufferSize(qint64 size) Q_DECL_OVERRIDE;

    // Similar to QIODevice's:
    qint64 encryptedBytesAvailable() const;
    qint64 encryptedBytesToWrite() const;

    // SSL configuration
    SslUnsafeConfiguration sslConfiguration() const;
    void setSslConfiguration(const SslUnsafeConfiguration &config);

    // Certificate & cipher accessors.
    void setLocalCertificateChain(const QList<SslUnsafeCertificate> &localChain);
    QList<SslUnsafeCertificate> localCertificateChain() const;

    void setLocalCertificate(const SslUnsafeCertificate &certificate);
    void setLocalCertificate(const QString &fileName, SslUnsafe::EncodingFormat format = SslUnsafe::Pem);
    SslUnsafeCertificate localCertificate() const;
    SslUnsafeCertificate peerCertificate() const;
    QList<SslUnsafeCertificate> peerCertificateChain() const;
    SslUnsafeCipher sessionCipher() const;
    SslUnsafe::SslProtocol sessionProtocol() const;

    // Private keys, for server sockets.
    void setPrivateKey(const SslUnsafeKey &key);
    void setPrivateKey(const QString &fileName, SslUnsafe::KeyAlgorithm algorithm = SslUnsafe::Rsa,
                       SslUnsafe::EncodingFormat format = SslUnsafe::Pem,
                       const QByteArray &passPhrase = QByteArray());
    SslUnsafeKey privateKey() const;

    // Cipher settings.
#if QT_DEPRECATED_SINCE(5, 5)
    QT_DEPRECATED_X("Use SslUnsafeConfiguration::ciphers()") QList<SslUnsafeCipher> ciphers() const;
    QT_DEPRECATED_X("Use SslUnsafeConfiguration::setCiphers()") void setCiphers(const QList<SslUnsafeCipher> &ciphers);
    QT_DEPRECATED void setCiphers(const QString &ciphers);
    QT_DEPRECATED static void setDefaultCiphers(const QList<SslUnsafeCipher> &ciphers);
    QT_DEPRECATED static QList<SslUnsafeCipher> defaultCiphers();
    QT_DEPRECATED_X("Use SslUnsafeConfiguration::supportedCiphers()") static QList<SslUnsafeCipher> supportedCiphers();
#endif // QT_DEPRECATED_SINCE(5, 5)

    // CA settings.
    bool addCaCertificates(const QString &path, SslUnsafe::EncodingFormat format = SslUnsafe::Pem,
                           QRegExp::PatternSyntax syntax = QRegExp::FixedString);
    void addCaCertificate(const SslUnsafeCertificate &certificate);
    void addCaCertificates(const QList<SslUnsafeCertificate> &certificates);
#if QT_DEPRECATED_SINCE(5, 5)
    QT_DEPRECATED_X("Use SslUnsafeConfiguration::setCaCertificates()") void setCaCertificates(const QList<SslUnsafeCertificate> &certificates);
    QT_DEPRECATED_X("Use SslUnsafeConfiguration::caCertificates()") QList<SslUnsafeCertificate> caCertificates() const;
#endif // QT_DEPRECATED_SINCE(5, 5)
    static bool addDefaultCaCertificates(const QString &path, SslUnsafe::EncodingFormat format = SslUnsafe::Pem,
                                         QRegExp::PatternSyntax syntax = QRegExp::FixedString);
    static void addDefaultCaCertificate(const SslUnsafeCertificate &certificate);
    static void addDefaultCaCertificates(const QList<SslUnsafeCertificate> &certificates);
#if QT_DEPRECATED_SINCE(5, 5)
    QT_DEPRECATED static void setDefaultCaCertificates(const QList<SslUnsafeCertificate> &certificates);
    QT_DEPRECATED static QList<SslUnsafeCertificate> defaultCaCertificates();
    QT_DEPRECATED_X("Use SslUnsafeConfiguration::systemCaCertificates()") static QList<SslUnsafeCertificate> systemCaCertificates();
#endif // QT_DEPRECATED_SINCE(5, 5)

    bool waitForConnected(int msecs = 30000) Q_DECL_OVERRIDE;
    bool waitForEncrypted(int msecs = 30000);
    bool waitForReadyRead(int msecs = 30000) Q_DECL_OVERRIDE;
    bool waitForBytesWritten(int msecs = 30000) Q_DECL_OVERRIDE;
    bool waitForDisconnected(int msecs = 30000) Q_DECL_OVERRIDE;

    QList<SslUnsafeError> sslErrors() const;

    static bool supportsSsl();
    static long sslLibraryVersionNumber();
    static QString sslLibraryVersionString();
    static long sslLibraryBuildVersionNumber();
    static QString sslLibraryBuildVersionString();

    void ignoreSslErrors(const QList<SslUnsafeError> &errors);

public Q_SLOTS:
    void startClientEncryption();
    void startServerEncryption();
    void ignoreSslErrors();

Q_SIGNALS:
    void encrypted();
    void peerVerifyError(const SslUnsafeError &error);
    void sslErrors(const QList<SslUnsafeError> &errors);
    void modeChanged(SslUnsafeSocket::SslMode newMode);
    void encryptedBytesWritten(qint64 totalBytes);
    void preSharedKeyAuthenticationRequired(SslUnsafePreSharedKeyAuthenticator *authenticator);

protected:
    qint64 readData(char *data, qint64 maxlen) Q_DECL_OVERRIDE;
    qint64 writeData(const char *data, qint64 len) Q_DECL_OVERRIDE;

private:
    QScopedPointer<SslUnsafeSocketBackendPrivate> d_ptr;
    Q_DECLARE_PRIVATE(SslUnsafeSocket)
    Q_DISABLE_COPY(SslUnsafeSocket)
    Q_PRIVATE_SLOT(d_func(), void _q_connectedSlot())
    Q_PRIVATE_SLOT(d_func(), void _q_hostFoundSlot())
    Q_PRIVATE_SLOT(d_func(), void _q_disconnectedSlot())
    Q_PRIVATE_SLOT(d_func(), void _q_stateChangedSlot(QAbstractSocket::SocketState))
    Q_PRIVATE_SLOT(d_func(), void _q_errorSlot(QAbstractSocket::SocketError))
    Q_PRIVATE_SLOT(d_func(), void _q_readyReadSlot())
    //Q_PRIVATE_SLOT(d_func(), void _q_channelReadyReadSlot(int))
    Q_PRIVATE_SLOT(d_func(), void _q_bytesWrittenSlot(qint64))
    //Q_PRIVATE_SLOT(d_func(), void _q_channelBytesWrittenSlot(int, qint64))
    Q_PRIVATE_SLOT(d_func(), void _q_readChannelFinishedSlot())
    Q_PRIVATE_SLOT(d_func(), void _q_flushWriteBuffer())
    Q_PRIVATE_SLOT(d_func(), void _q_flushReadBuffer())
    Q_PRIVATE_SLOT(d_func(), void _q_resumeImplementation())
#if defined(Q_OS_WIN) && !defined(Q_OS_WINRT)
    Q_PRIVATE_SLOT(d_func(), void _q_caRootLoaded(SslUnsafeCertificate,SslUnsafeCertificate))
#endif
    friend class SslUnsafeSocketBackendPrivate;
};

#endif // QT_NO_SSL

QT_END_NAMESPACE

#endif
