#ifndef SSLUNSAFESOCKET_H
#define SSLUNSAFESOCKET_H

#include <QTcpSocket>

#include "sslunsafe.h"
//#include "sslunsafeconfiguration.h"

#include "sslunsafecertificate.h"
#include "sslunsafecipher.h"

class SslUnsafeConfiguration;
class SslUnsafePreSharedKeyAuthenticator;

class QHostAddress;

class SslUnsafeSocketPrivate;
class SslUnsafeSocketBackendPrivate;
class SslUnsafeSocket : public QTcpSocket
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
    qint64 bytesAvailable() const;
    qint64 bytesToWrite() const;
    bool canReadLine() const;
    void close();
    bool atEnd() const;
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

    // CA settings.
    bool addCaCertificates(const QString &path, SslUnsafe::EncodingFormat format = SslUnsafe::Pem,
                           QRegExp::PatternSyntax syntax = QRegExp::FixedString);
    void addCaCertificate(const SslUnsafeCertificate &certificate);
    void addCaCertificates(const QList<SslUnsafeCertificate> &certificates);
    static bool addDefaultCaCertificates(const QString &path, SslUnsafe::EncodingFormat format = SslUnsafe::Pem,
                                         QRegExp::PatternSyntax syntax = QRegExp::FixedString);
    static void addDefaultCaCertificate(const SslUnsafeCertificate &certificate);
    static void addDefaultCaCertificates(const QList<SslUnsafeCertificate> &certificates);

    bool waitForConnected(int msecs = 30000) Q_DECL_OVERRIDE;
    bool waitForEncrypted(int msecs = 30000);
    bool waitForReadyRead(int msecs = 30000);
    bool waitForBytesWritten(int msecs = 30000);
    bool waitForDisconnected(int msecs = 30000) Q_DECL_OVERRIDE;

    QList<SslUnsafeError> sslErrors() const;

    static bool supportsSsl();
    static long sslLibraryVersionNumber();
    static QString sslLibraryVersionString();
    static long sslLibraryBuildVersionNumber();
    static QString sslLibraryBuildVersionString();

    void ignoreSslErrors(const QList<SslUnsafeError> &errors);

public slots:
    void startClientEncryption();
    void startServerEncryption();
    void ignoreSslErrors();

signals:
    void encrypted();
    void peerVerifyError(const SslUnsafeError &error);
    void sslErrors(const QList<SslUnsafeError> &errors);
    void modeChanged(SslUnsafeSocket::SslMode newMode);
    void encryptedBytesWritten(qint64 totalBytes);
    void preSharedKeyAuthenticationRequired(SslUnsafePreSharedKeyAuthenticator *authenticator);

protected:
    qint64 readData(char *data, qint64 maxlen);
    qint64 writeData(const char *data, qint64 len);

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

    friend class SslUnsafeSocketBackendPrivate;
};

#endif
