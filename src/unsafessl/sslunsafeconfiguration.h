#ifndef SSLUNSAFECONFIGURATION_H
#define SSLUNSAFECONFIGURATION_H

//#include <QtNetwork/qtnetworkglobal.h>
#include <QtCore/qshareddata.h>

#include "sslunsafesocket.h"
#include <QtNetwork/qssl.h>

#ifndef QT_NO_SSL

template<typename T> class QList;
class SslUnsafeCertificate;
class SslUnsafeCipher;
class SslUnsafeKey;
class SslUnsafeEllipticCurve;
class SslUnsafeDiffieHellmanParameters;

class SslUnsafeConfigurationPrivate;
class SslUnsafeConfiguration
{
public:
    SslUnsafeConfiguration();
    SslUnsafeConfiguration(const SslUnsafeConfiguration &other);
    ~SslUnsafeConfiguration();
#ifdef Q_COMPILER_RVALUE_REFS
    SslUnsafeConfiguration &operator=(SslUnsafeConfiguration &&other) Q_DECL_NOTHROW { swap(other); return *this; }
#endif
    SslUnsafeConfiguration &operator=(const SslUnsafeConfiguration &other);

    void swap(SslUnsafeConfiguration &other) Q_DECL_NOTHROW
    { qSwap(d, other.d); }

    bool operator==(const SslUnsafeConfiguration &other) const;
    inline bool operator!=(const SslUnsafeConfiguration &other) const
    { return !(*this == other); }

    bool isNull() const;

    QSsl::SslProtocol protocol() const;
    void setProtocol(QSsl::SslProtocol protocol);

    // Verification
    SslUnsafeSocket::PeerVerifyMode peerVerifyMode() const;
    void setPeerVerifyMode(SslUnsafeSocket::PeerVerifyMode mode);

    int peerVerifyDepth() const;
    void setPeerVerifyDepth(int depth);

    // Certificate & cipher configuration
    QList<SslUnsafeCertificate> localCertificateChain() const;
    void setLocalCertificateChain(const QList<SslUnsafeCertificate> &localChain);

    SslUnsafeCertificate localCertificate() const;
    void setLocalCertificate(const SslUnsafeCertificate &certificate);

    SslUnsafeCertificate peerCertificate() const;
    QList<SslUnsafeCertificate> peerCertificateChain() const;
    SslUnsafeCipher sessionCipher() const;
    QSsl::SslProtocol sessionProtocol() const;

    // Private keys, for server sockets
    SslUnsafeKey privateKey() const;
    void setPrivateKey(const SslUnsafeKey &key);

    // Cipher settings
    QList<SslUnsafeCipher> ciphers() const;
    void setCiphers(const QList<SslUnsafeCipher> &ciphers);
    static QList<SslUnsafeCipher> supportedCiphers();

    // Certificate Authority (CA) settings
    QList<SslUnsafeCertificate> caCertificates() const;
    void setCaCertificates(const QList<SslUnsafeCertificate> &certificates);
    static QList<SslUnsafeCertificate> systemCaCertificates();

    void setSslOption(QSsl::SslOption option, bool on);
    bool testSslOption(QSsl::SslOption option) const;

    QByteArray sessionTicket() const;
    void setSessionTicket(const QByteArray &sessionTicket);
    int sessionTicketLifeTimeHint() const;

    SslUnsafeKey ephemeralServerKey() const;

    // EC settings
    QVector<SslUnsafeEllipticCurve> ellipticCurves() const;
    void setEllipticCurves(const QVector<SslUnsafeEllipticCurve> &curves);
    static QVector<SslUnsafeEllipticCurve> supportedEllipticCurves();

    QByteArray preSharedKeyIdentityHint() const;
    void setPreSharedKeyIdentityHint(const QByteArray &hint);

    SslUnsafeDiffieHellmanParameters diffieHellmanParameters() const;
    void setDiffieHellmanParameters(const SslUnsafeDiffieHellmanParameters &dhparams);

    static SslUnsafeConfiguration defaultConfiguration();
    static void setDefaultConfiguration(const SslUnsafeConfiguration &configuration);

    enum NextProtocolNegotiationStatus {
        NextProtocolNegotiationNone,
        NextProtocolNegotiationNegotiated,
        NextProtocolNegotiationUnsupported
    };

#if QT_VERSION >= QT_VERSION_CHECK(6,0,0)
    void setAllowedNextProtocols(const QList<QByteArray> &protocols);
#else
    void setAllowedNextProtocols(QList<QByteArray> protocols);
#endif
    QList<QByteArray> allowedNextProtocols() const;

    QByteArray nextNegotiatedProtocol() const;
    NextProtocolNegotiationStatus nextProtocolNegotiationStatus() const;

    static const char ALPNProtocolHTTP2[];
    static const char NextProtocolSpdy3_0[];
    static const char NextProtocolHttp1_1[];

private:
    friend class SslUnsafeSocket;
    friend class SslUnsafeConfigurationPrivate;
    friend class SslUnsafeSocketBackendPrivate;
    friend class SslUnsafeContext;
    SslUnsafeConfiguration(SslUnsafeConfigurationPrivate *dd);
    QSharedDataPointer<SslUnsafeConfigurationPrivate> d;
};

Q_DECLARE_SHARED(SslUnsafeConfiguration)

Q_DECLARE_METATYPE(SslUnsafeConfiguration)

#endif  // QT_NO_SSL

#endif
