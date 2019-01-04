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


#ifndef SSLUNSAFESOCKET_P_H
#define SSLUNSAFESOCKET_P_H

#include "sslunsafesocket.h"

//
//  W A R N I N G
//  -------------
//
// This file is not part of the Qt API. It exists purely as an
// implementation detail. This header file may change from version to
// version without notice, or even be removed.
//
// We mean it.
//

//#include <QtNetwork/private/qtnetworkglobal_p.h>
//#include <private/qtcpsocket_p.h>
#include "sslunsafekey.h"
#include "sslunsafeconfiguration_p.h"
#ifndef QT_NO_OPENSSL
#include "sslunsafecontext_openssl_p.h"
#else
class SslUnsafeContext;
#endif

#include <QtCore/qstringlist.h>

#include "sslunsaferingbuffer_p.h"

#if defined(Q_OS_MAC)
#include <Security/SecCertificate.h>
#include <CoreFoundation/CFArray.h>
#elif defined(Q_OS_WIN)
#include <QtCore/qt_windows.h>
#ifndef Q_OS_WINRT
#include <wincrypt.h>
#endif // !Q_OS_WINRT
#ifndef HCRYPTPROV_LEGACY
#define HCRYPTPROV_LEGACY HCRYPTPROV
#endif // !HCRYPTPROV_LEGACY
#endif // Q_OS_WIN

QT_BEGIN_NAMESPACE

#if defined(Q_OS_MACX)
    typedef CFDataRef (*PtrSecCertificateCopyData)(SecCertificateRef);
    typedef OSStatus (*PtrSecTrustSettingsCopyCertificates)(int, CFArrayRef*);
    typedef OSStatus (*PtrSecTrustCopyAnchorCertificates)(CFArrayRef*);
#endif

#if defined(Q_OS_WIN) && !defined(Q_OS_WINRT)
    typedef HCERTSTORE (WINAPI *PtrCertOpenSystemStoreW)(HCRYPTPROV_LEGACY, LPCWSTR);
    typedef PCCERT_CONTEXT (WINAPI *PtrCertFindCertificateInStore)(HCERTSTORE, DWORD, DWORD, DWORD, const void*, PCCERT_CONTEXT);
    typedef BOOL (WINAPI *PtrCertCloseStore)(HCERTSTORE, DWORD);
#endif // Q_OS_WIN && !Q_OS_WINRT


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
    static bool addDefaultCaCertificates(const QString &path, SslUnsafe::EncodingFormat format,
                                         QRegExp::PatternSyntax syntax);
    static void addDefaultCaCertificate(const SslUnsafeCertificate &cert);
    static void addDefaultCaCertificates(const QList<SslUnsafeCertificate> &certs);
    Q_AUTOTEST_EXPORT static bool isMatchingHostname(const SslUnsafeCertificate &cert,
                                                     const QString &peerName);
    Q_AUTOTEST_EXPORT static bool isMatchingHostname(const QString &cn, const QString &hostname);

#if defined(Q_OS_WIN) && !defined(Q_OS_WINRT)
    static PtrCertOpenSystemStoreW ptrCertOpenSystemStoreW;
    static PtrCertFindCertificateInStore ptrCertFindCertificateInStore;
    static PtrCertCloseStore ptrCertCloseStore;
#endif // Q_OS_WIN && !Q_OS_WINRT

    // The socket itself, including private slots.
    QTcpSocket *plainSocket;
    void createPlainSocket(QIODevice::OpenMode openMode);
    static void pauseSocketNotifiers(SslUnsafeSocket*);
    static void resumeSocketNotifiers(SslUnsafeSocket*);
    // ### The 2 methods below should be made member methods once the SslUnsafeContext class is made public
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
    void _q_resumeImplementation();
#if defined(Q_OS_WIN) && !defined(Q_OS_WINRT)
    virtual void _q_caRootLoaded(SslUnsafeCertificate,SslUnsafeCertificate) = 0;
#endif

    static QList<QByteArray> unixRootCertDirectories(); // used also by SslUnsafeContext

    virtual qint64 peek(char *data, qint64 maxSize);// Q_DECL_OVERRIDE;
    virtual QByteArray peek(qint64 maxSize);// Q_DECL_OVERRIDE;
    bool flush();// Q_DECL_OVERRIDE;

    // Platform specific functions
    virtual void startClientEncryption() = 0;
    virtual void startServerEncryption() = 0;
    virtual void transmit() = 0;
    virtual void disconnectFromHost() = 0;
    virtual void disconnected() = 0;
    virtual SslUnsafeCipher sessionCipher() const = 0;
    virtual SslUnsafe::SslProtocol sessionProtocol() const = 0;
    virtual void continueHandshake() = 0;

    Q_AUTOTEST_EXPORT static bool rootCertOnDemandLoadingSupported();

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
    qint64 transactionPos;

private:
    static bool ensureLibraryLoaded();
    static void ensureCiphersAndCertsLoaded();
#if defined(Q_OS_ANDROID)
    static QList<QByteArray> fetchSslCertificateData();
#endif

    static bool s_libraryLoaded;
    static bool s_loadedCiphersAndCerts;
    // from qabstractsocket_p.h
    QAbstractSocket::SocketError socketError;
protected:
    bool verifyErrorsHaveBeenIgnored();
    bool paused;
    bool flushTriggered;
};

QT_END_NAMESPACE

#endif
