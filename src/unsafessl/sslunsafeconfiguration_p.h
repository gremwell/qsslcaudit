#ifndef SSLUNSAFECONFIGURATION_P_H
#define SSLUNSAFECONFIGURATION_P_H

//#include <QtNetwork/private/qtnetworkglobal_p.h>
#include "sslunsafeconfiguration.h"
#include "qlist.h"
#include "sslunsafecertificate.h"
#include "sslunsafecipher.h"
#include "sslunsafekey.h"
#include "sslunsafeellipticcurve.h"
#include "sslunsafediffiehellmanparameters.h"

class SslUnsafeConfigurationPrivate: public QSharedData
{
public:
    SslUnsafeConfigurationPrivate()
        : sessionProtocol(QSsl::UnknownProtocol),
          protocol(QSsl::SecureProtocols),
          peerVerifyMode(SslUnsafeSocket::AutoVerifyPeer),
          peerVerifyDepth(0),
          allowRootCertOnDemandLoading(true),
          peerSessionShared(false),
          sslOptions(SslUnsafeConfigurationPrivate::defaultSslOptions),
          dhParams(SslUnsafeDiffieHellmanParameters::defaultParameters()),
          sslSessionTicketLifeTimeHint(-1),
          ephemeralServerKey(),
          preSharedKeyIdentityHint(),
          nextProtocolNegotiationStatus(SslUnsafeConfiguration::NextProtocolNegotiationNone)
    { }

    SslUnsafeCertificate peerCertificate;
    QList<SslUnsafeCertificate> peerCertificateChain;

    QList<SslUnsafeCertificate> localCertificateChain;

    SslUnsafeKey privateKey;
    SslUnsafeCipher sessionCipher;
    QSsl::SslProtocol sessionProtocol;
    QList<SslUnsafeCipher> ciphers;
    QList<SslUnsafeCertificate> caCertificates;

    QSsl::SslProtocol protocol;
    SslUnsafeSocket::PeerVerifyMode peerVerifyMode;
    int peerVerifyDepth;
    bool allowRootCertOnDemandLoading;
    bool peerSessionShared;

    static bool peerSessionWasShared(const SslUnsafeConfiguration &configuration);

    QSsl::SslOptions sslOptions;

    static const QSsl::SslOptions defaultSslOptions;

    QVector<SslUnsafeEllipticCurve> ellipticCurves;

    SslUnsafeDiffieHellmanParameters dhParams;

    QByteArray sslSession;
    int sslSessionTicketLifeTimeHint;

    SslUnsafeKey ephemeralServerKey;

    QByteArray preSharedKeyIdentityHint;

    QList<QByteArray> nextAllowedProtocols;
    QByteArray nextNegotiatedProtocol;
    SslUnsafeConfiguration::NextProtocolNegotiationStatus nextProtocolNegotiationStatus;

    // in sslunsafesocket.cpp:
    static SslUnsafeConfiguration defaultConfiguration();
    static void setDefaultConfiguration(const SslUnsafeConfiguration &configuration);
    static void deepCopyDefaultConfiguration(SslUnsafeConfigurationPrivate *config);
};

// implemented here for inlining purposes
inline SslUnsafeConfiguration::SslUnsafeConfiguration(SslUnsafeConfigurationPrivate *dd)
    : d(dd)
{
}

#endif
