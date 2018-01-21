
//#include "qssl_p.h"
#include "sslunsafeconfiguration.h"
#include "sslunsafeconfiguration_p.h"
#include "sslunsafesocket.h"
#include "sslunsafesocket_p.h"
#include "qmutex.h"
#include "qdebug.h"

const QSsl::SslOptions SslUnsafeConfigurationPrivate::defaultSslOptions = QSsl::SslOptionDisableEmptyFragments
                                                                    |QSsl::SslOptionDisableLegacyRenegotiation
                                                                    |QSsl::SslOptionDisableCompression
                                                                    |QSsl::SslOptionDisableSessionPersistence;

const char SslUnsafeConfiguration::ALPNProtocolHTTP2[] = "h2";
const char SslUnsafeConfiguration::NextProtocolSpdy3_0[] = "spdy/3";
const char SslUnsafeConfiguration::NextProtocolHttp1_1[] = "http/1.1";

SslUnsafeConfiguration::SslUnsafeConfiguration()
    : d(new SslUnsafeConfigurationPrivate)
{
}

SslUnsafeConfiguration::SslUnsafeConfiguration(const SslUnsafeConfiguration &other)
    : d(other.d)
{
}

SslUnsafeConfiguration::~SslUnsafeConfiguration()
{
    // QSharedDataPointer deletes d for us if necessary
}

SslUnsafeConfiguration &SslUnsafeConfiguration::operator=(const SslUnsafeConfiguration &other)
{
    d = other.d;
    return *this;
}

bool SslUnsafeConfiguration::operator==(const SslUnsafeConfiguration &other) const
{
    if (d == other.d)
        return true;
    return d->peerCertificate == other.d->peerCertificate &&
        d->peerCertificateChain == other.d->peerCertificateChain &&
        d->localCertificateChain == other.d->localCertificateChain &&
        d->privateKey == other.d->privateKey &&
        d->sessionCipher == other.d->sessionCipher &&
        d->sessionProtocol == other.d->sessionProtocol &&
        d->preSharedKeyIdentityHint == other.d->preSharedKeyIdentityHint &&
        d->ciphers == other.d->ciphers &&
        d->ellipticCurves == other.d->ellipticCurves &&
        d->ephemeralServerKey == other.d->ephemeralServerKey &&
        d->dhParams == other.d->dhParams &&
        d->caCertificates == other.d->caCertificates &&
        d->protocol == other.d->protocol &&
        d->peerVerifyMode == other.d->peerVerifyMode &&
        d->peerVerifyDepth == other.d->peerVerifyDepth &&
        d->allowRootCertOnDemandLoading == other.d->allowRootCertOnDemandLoading &&
        d->sslOptions == other.d->sslOptions &&
        d->sslSession == other.d->sslSession &&
        d->sslSessionTicketLifeTimeHint == other.d->sslSessionTicketLifeTimeHint &&
        d->nextAllowedProtocols == other.d->nextAllowedProtocols &&
        d->nextNegotiatedProtocol == other.d->nextNegotiatedProtocol &&
        d->nextProtocolNegotiationStatus == other.d->nextProtocolNegotiationStatus;
}

bool SslUnsafeConfiguration::isNull() const
{
    return (d->protocol == QSsl::SecureProtocols &&
            d->peerVerifyMode == SslUnsafeSocket::AutoVerifyPeer &&
            d->peerVerifyDepth == 0 &&
            d->allowRootCertOnDemandLoading == true &&
            d->caCertificates.count() == 0 &&
            d->ciphers.count() == 0 &&
            d->ellipticCurves.isEmpty() &&
            d->ephemeralServerKey.isNull() &&
            d->dhParams == SslUnsafeDiffieHellmanParameters::defaultParameters() &&
            d->localCertificateChain.isEmpty() &&
            d->privateKey.isNull() &&
            d->peerCertificate.isNull() &&
            d->peerCertificateChain.count() == 0 &&
            d->sslOptions == SslUnsafeConfigurationPrivate::defaultSslOptions &&
            d->sslSession.isNull() &&
            d->sslSessionTicketLifeTimeHint == -1 &&
            d->preSharedKeyIdentityHint.isNull() &&
            d->nextAllowedProtocols.isEmpty() &&
            d->nextNegotiatedProtocol.isNull() &&
            d->nextProtocolNegotiationStatus == SslUnsafeConfiguration::NextProtocolNegotiationNone);
}

QSsl::SslProtocol SslUnsafeConfiguration::protocol() const
{
    return d->protocol;
}

void SslUnsafeConfiguration::setProtocol(QSsl::SslProtocol protocol)
{
    d->protocol = protocol;
}

SslUnsafeSocket::PeerVerifyMode SslUnsafeConfiguration::peerVerifyMode() const
{
    return d->peerVerifyMode;
}

void SslUnsafeConfiguration::setPeerVerifyMode(SslUnsafeSocket::PeerVerifyMode mode)
{
    d->peerVerifyMode = mode;
}


int SslUnsafeConfiguration::peerVerifyDepth() const
{
    return d->peerVerifyDepth;
}

void SslUnsafeConfiguration::setPeerVerifyDepth(int depth)
{
    if (depth < 0) {
        qWarning() << "SslUnsafeConfiguration::setPeerVerifyDepth: cannot set negative depth of " << depth;
        return;
    }
    d->peerVerifyDepth = depth;
}

QList<SslUnsafeCertificate> SslUnsafeConfiguration::localCertificateChain() const
{
    return d->localCertificateChain;
}

void SslUnsafeConfiguration::setLocalCertificateChain(const QList<SslUnsafeCertificate> &localChain)
{
    d->localCertificateChain = localChain;
}

SslUnsafeCertificate SslUnsafeConfiguration::localCertificate() const
{
    if (d->localCertificateChain.isEmpty())
        return SslUnsafeCertificate();
    return d->localCertificateChain[0];
}

void SslUnsafeConfiguration::setLocalCertificate(const SslUnsafeCertificate &certificate)
{
    d->localCertificateChain = QList<SslUnsafeCertificate>();
    d->localCertificateChain += certificate;
}

SslUnsafeCertificate SslUnsafeConfiguration::peerCertificate() const
{
    return d->peerCertificate;
}

QList<SslUnsafeCertificate> SslUnsafeConfiguration::peerCertificateChain() const
{
    return d->peerCertificateChain;
}

SslUnsafeCipher SslUnsafeConfiguration::sessionCipher() const
{
    return d->sessionCipher;
}

QSsl::SslProtocol SslUnsafeConfiguration::sessionProtocol() const
{
    return d->sessionProtocol;
}

SslUnsafeKey SslUnsafeConfiguration::privateKey() const
{
    return d->privateKey;
}

void SslUnsafeConfiguration::setPrivateKey(const SslUnsafeKey &key)
{
    d->privateKey = key;
}

QList<SslUnsafeCipher> SslUnsafeConfiguration::ciphers() const
{
    return d->ciphers;
}

void SslUnsafeConfiguration::setCiphers(const QList<SslUnsafeCipher> &ciphers)
{
    d->ciphers = ciphers;
}

QList<SslUnsafeCipher> SslUnsafeConfiguration::supportedCiphers()
{
    return SslUnsafeSocketPrivate::supportedCiphers();
}

QList<SslUnsafeCertificate> SslUnsafeConfiguration::caCertificates() const
{
    return d->caCertificates;
}

void SslUnsafeConfiguration::setCaCertificates(const QList<SslUnsafeCertificate> &certificates)
{
    d->caCertificates = certificates;
    d->allowRootCertOnDemandLoading = false;
}

QList<SslUnsafeCertificate> SslUnsafeConfiguration::systemCaCertificates()
{
    // we are calling ensureInitialized() in the method below
    return SslUnsafeSocketPrivate::systemCaCertificates();
}

void SslUnsafeConfiguration::setSslOption(QSsl::SslOption option, bool on)
{
    if (on)
        d->sslOptions |= option;
    else
        d->sslOptions &= ~option;
    //d->sslOptions.setFlag(option, on);
}

bool SslUnsafeConfiguration::testSslOption(QSsl::SslOption option) const
{
    return d->sslOptions & option;
}

QByteArray SslUnsafeConfiguration::sessionTicket() const
{
    return d->sslSession;
}

void SslUnsafeConfiguration::setSessionTicket(const QByteArray &sessionTicket)
{
    d->sslSession = sessionTicket;
}

int SslUnsafeConfiguration::sessionTicketLifeTimeHint() const
{
    return d->sslSessionTicketLifeTimeHint;
}

SslUnsafeKey SslUnsafeConfiguration::ephemeralServerKey() const
{
    return d->ephemeralServerKey;
}

QVector<SslUnsafeEllipticCurve> SslUnsafeConfiguration::ellipticCurves() const
{
    return d->ellipticCurves;
}

void SslUnsafeConfiguration::setEllipticCurves(const QVector<SslUnsafeEllipticCurve> &curves)
{
    d->ellipticCurves = curves;
}

QVector<SslUnsafeEllipticCurve> SslUnsafeConfiguration::supportedEllipticCurves()
{
    return SslUnsafeSocketPrivate::supportedEllipticCurves();
}

QByteArray SslUnsafeConfiguration::preSharedKeyIdentityHint() const
{
    return d->preSharedKeyIdentityHint;
}

void SslUnsafeConfiguration::setPreSharedKeyIdentityHint(const QByteArray &hint)
{
    d->preSharedKeyIdentityHint = hint;
}

SslUnsafeDiffieHellmanParameters SslUnsafeConfiguration::diffieHellmanParameters() const
{
    return d->dhParams;
}

void SslUnsafeConfiguration::setDiffieHellmanParameters(const SslUnsafeDiffieHellmanParameters &dhparams)
{
    d->dhParams = dhparams;
}

QByteArray SslUnsafeConfiguration::nextNegotiatedProtocol() const
{
    return d->nextNegotiatedProtocol;
}

#if QT_VERSION >= QT_VERSION_CHECK(6,0,0)
void SslUnsafeConfiguration::setAllowedNextProtocols(const QList<QByteArray> &protocols)
#else
void SslUnsafeConfiguration::setAllowedNextProtocols(QList<QByteArray> protocols)
#endif
{
    d->nextAllowedProtocols = protocols;
}

QList<QByteArray> SslUnsafeConfiguration::allowedNextProtocols() const
{
    return d->nextAllowedProtocols;
}

SslUnsafeConfiguration::NextProtocolNegotiationStatus SslUnsafeConfiguration::nextProtocolNegotiationStatus() const
{
    return d->nextProtocolNegotiationStatus;
}

SslUnsafeConfiguration SslUnsafeConfiguration::defaultConfiguration()
{
    return SslUnsafeConfigurationPrivate::defaultConfiguration();
}

void SslUnsafeConfiguration::setDefaultConfiguration(const SslUnsafeConfiguration &configuration)
{
    SslUnsafeConfigurationPrivate::setDefaultConfiguration(configuration);
}

bool SslUnsafeConfigurationPrivate::peerSessionWasShared(const SslUnsafeConfiguration &configuration) {
        return configuration.d->peerSessionShared;
    }
