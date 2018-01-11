#ifndef SSLUNSAFESOCKET_P_H
#define SSLUNSAFESOCKET_P_H

#include "sslunsafesocket.h"

#include <qobject.h>
//#include <QtNetwork/private/qtnetworkglobal_p.h>

#include "sslunsafekey.h"

#include "sslunsafeconfiguration_p.h"

#include "sslunsafecontext_openssl_p.h"

#include <QtCore/qstringlist.h>

#include "sslunsaferingbuffer_p.h"


int qt_subtract_from_timeout(int timeout, int elapsed);

class SslUnsafeSocketPrivate : public QObjectData, public QTcpSocket // public QTcpSocketPrivate
{
    Q_DECLARE_PUBLIC(SslUnsafeSocket)
public:
    SslUnsafeSocketPrivate();
    virtual ~SslUnsafeSocketPrivate();

    void init();
    bool initialized;

    SslUnsafeSocket::SslMode mode;
    bool autoStartHandshake;
    bool connectionEncrypted;
    bool shutdown;
    bool ignoreAllSslErrors;
    QList<SslUnsafeError> ignoreErrorsList;
    bool* readyReadEmittedPointer;

    SslUnsafeConfigurationPrivate configuration;
    QList<SslUnsafeError> sslErrors;
    QSharedPointer<SslUnsafeContext> sslContextPointer;

    // if set, this hostname is used for certificate validation instead of the hostname
    // that was used for connecting to.
    QString verificationPeerName;

    bool allowRootCertOnDemandLoading;

    static bool s_loadRootCertsOnDemand;

    static bool supportsSsl();
    static long sslLibraryVersionNumber();
    static QString sslLibraryVersionString();
    static long sslLibraryBuildVersionNumber();
    static QString sslLibraryBuildVersionString();
    static void ensureInitialized();
    static void deinitialize();
    static QList<SslUnsafeCipher> defaultCiphers();
    static QList<SslUnsafeCipher> supportedCiphers();
    static void setDefaultCiphers(const QList<SslUnsafeCipher> &ciphers);
    static void setDefaultSupportedCiphers(const QList<SslUnsafeCipher> &ciphers);
    static void resetDefaultCiphers();

    static QVector<SslUnsafeEllipticCurve> supportedEllipticCurves();
    static void setDefaultSupportedEllipticCurves(const QVector<SslUnsafeEllipticCurve> &curves);
    static void resetDefaultEllipticCurves();

    static QList<SslUnsafeCertificate> defaultCaCertificates();
    static QList<SslUnsafeCertificate> systemCaCertificates();
    static void setDefaultCaCertificates(const QList<SslUnsafeCertificate> &certs);
    static bool addDefaultCaCertificates(const QString &path, QSsl::EncodingFormat format,
                                         QRegExp::PatternSyntax syntax);
    static void addDefaultCaCertificate(const SslUnsafeCertificate &cert);
    static void addDefaultCaCertificates(const QList<SslUnsafeCertificate> &certs);
    static bool isMatchingHostname(const SslUnsafeCertificate &cert, const QString &peerName);
    static bool isMatchingHostname(const QString &cn, const QString &hostname);

    // The socket itself, including private slots.
    QTcpSocket *plainSocket;
    void createPlainSocket(QIODevice::OpenMode openMode);
    static void pauseSocketNotifiers(SslUnsafeSocket*);
    static void resumeSocketNotifiers(SslUnsafeSocket*);
    // ### The 2 methods below should be made member methods once the QSslContext class is made public
    static void checkSettingSslContext(SslUnsafeSocket*, QSharedPointer<SslUnsafeContext>);
    static QSharedPointer<SslUnsafeContext> sslContext(SslUnsafeSocket *socket);
    bool isPaused() const;
    bool bind(const QHostAddress &address, quint16, QAbstractSocket::BindMode);// Q_DECL_OVERRIDE;
    void _q_connectedSlot();
    void _q_hostFoundSlot();
    void _q_disconnectedSlot();
    void _q_stateChangedSlot(QAbstractSocket::SocketState);
    void _q_errorSlot(QAbstractSocket::SocketError);
    void _q_readyReadSlot();
    void _q_channelReadyReadSlot(int);
    void _q_bytesWrittenSlot(qint64);
    void _q_channelBytesWrittenSlot(int, qint64);
    void _q_readChannelFinishedSlot();
    void _q_flushWriteBuffer();
    void _q_flushReadBuffer();

    static QList<QByteArray> unixRootCertDirectories(); // used also by QSslContext

    virtual qint64 peek(char *data, qint64 maxSize);// Q_DECL_OVERRIDE;
    virtual QByteArray peek(qint64 maxSize);// Q_DECL_OVERRIDE;
    virtual bool flush();

    // Platform specific functions
    virtual void startClientEncryption() = 0;
    virtual void startServerEncryption() = 0;
    virtual void transmit() = 0;
    virtual void disconnectFromHost() = 0;
    virtual void disconnected() = 0;
    virtual SslUnsafeCipher sessionCipher() const = 0;
    virtual QSsl::SslProtocol sessionProtocol() const = 0;
    virtual void continueHandshake() = 0;

    static bool rootCertOnDemandLoadingSupported();

    // from qabstractsocket_p.h
    void setErrorAndEmit(QAbstractSocket::SocketError errorCode, const QString &errorString);
    qint64 readBufferMaxSize;
    void setError(QAbstractSocket::SocketError errorCode, const QString &errorString);
    qintptr cachedSocketDescriptor;
    QAbstractSocket::NetworkLayerProtocol preferredNetworkLayerProtocol;
    bool pendingClose;
    bool emittedBytesWritten;

    // from qiodevice_p.h
    class QRingBufferRef {
        SslUnsafeRingBuffer *m_buf;
        inline QRingBufferRef() : m_buf(Q_NULLPTR) { }
        friend class SslUnsafeSocketPrivate;
    public:
        // wrap functions from QRingBuffer
        inline void setChunkSize(int size) { Q_ASSERT(m_buf); m_buf->setChunkSize(size); }
        inline int chunkSize() const { Q_ASSERT(m_buf); return m_buf->chunkSize(); }
        inline qint64 nextDataBlockSize() const { return (m_buf ? m_buf->nextDataBlockSize() : Q_INT64_C(0)); }
        inline const char *readPointer() const { return (m_buf ? m_buf->readPointer() : Q_NULLPTR); }
        inline const char *readPointerAtPosition(qint64 pos, qint64 &length) const { Q_ASSERT(m_buf); return m_buf->readPointerAtPosition(pos, length); }
        inline void free(qint64 bytes) { Q_ASSERT(m_buf); m_buf->free(bytes); }
        inline char *reserve(qint64 bytes) { Q_ASSERT(m_buf); return m_buf->reserve(bytes); }
        inline char *reserveFront(qint64 bytes) { Q_ASSERT(m_buf); return m_buf->reserveFront(bytes); }
        inline void truncate(qint64 pos) { Q_ASSERT(m_buf); m_buf->truncate(pos); }
        inline void chop(qint64 bytes) { Q_ASSERT(m_buf); m_buf->chop(bytes); }
        inline bool isEmpty() const { return !m_buf || m_buf->isEmpty(); }
        inline int getChar() { return (m_buf ? m_buf->getChar() : -1); }
        inline void putChar(char c) { Q_ASSERT(m_buf); m_buf->putChar(c); }
        inline void ungetChar(char c) { Q_ASSERT(m_buf); m_buf->ungetChar(c); }
        inline qint64 size() const { return (m_buf ? m_buf->size() : Q_INT64_C(0)); }
        inline void clear() { if (m_buf) m_buf->clear(); }
        inline qint64 indexOf(char c) const { return (m_buf ? m_buf->indexOf(c, m_buf->size()) : Q_INT64_C(-1)); }
        inline qint64 indexOf(char c, qint64 maxLength, qint64 pos = 0) const { return (m_buf ? m_buf->indexOf(c, maxLength, pos) : Q_INT64_C(-1)); }
        inline qint64 read(char *data, qint64 maxLength) { return (m_buf ? m_buf->read(data, maxLength) : Q_INT64_C(0)); }
        inline QByteArray read() { return (m_buf ? m_buf->read() : QByteArray()); }
        inline qint64 peek(char *data, qint64 maxLength, qint64 pos = 0) const { return (m_buf ? m_buf->peek(data, maxLength, pos) : Q_INT64_C(0)); }
        inline void append(const char *data, qint64 size) { Q_ASSERT(m_buf); m_buf->append(data, size); }
        inline void append(const QByteArray &qba) { Q_ASSERT(m_buf); m_buf->append(qba); }
        inline qint64 skip(qint64 length) { return (m_buf ? m_buf->skip(length) : Q_INT64_C(0)); }
        inline qint64 readLine(char *data, qint64 maxLength) { return (m_buf ? m_buf->readLine(data, maxLength) : Q_INT64_C(-1)); }
        inline bool canReadLine() const { return m_buf && m_buf->canReadLine(); }
    };

    QList<SslUnsafeRingBuffer> readBuffers;
    QList<SslUnsafeRingBuffer> writeBuffers;

    QRingBufferRef buffer;
    QRingBufferRef writeBuffer;
    qint64 pos;
    qint64 devicePos;
    int readChannelCount;
    int writeChannelCount;
    int currentReadChannel;
    int currentWriteChannel;
    int readBufferChunkSize;
    int writeBufferChunkSize;
    qint64 transactionPos;
    bool transactionStarted;
    bool baseReadLineDataCalled;

private:
    static bool ensureLibraryLoaded();
    static void ensureCiphersAndCertsLoaded();

    static bool s_libraryLoaded;
    static bool s_loadedCiphersAndCerts;

    // from qabstractsocket_p.h
    QAbstractSocket::SocketError socketError;

protected:
    bool verifyErrorsHaveBeenIgnored();
    bool paused;
};

#endif
