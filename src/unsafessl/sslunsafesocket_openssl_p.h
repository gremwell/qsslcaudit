#ifndef SSLUNSAFESOCKET_OPENSSL_P_H
#define SSLUNSAFESOCKET_OPENSSL_P_H


//#include <QtNetwork/private/qtnetworkglobal_p.h>
#include "sslunsafesocket_p.h"

#ifdef Q_OS_WIN
#include <qt_windows.h>
#if defined(OCSP_RESPONSE)
#undef OCSP_RESPONSE
#endif
#if defined(X509_NAME)
#undef X509_NAME
#endif
#endif // Q_OS_WIN

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/tls1.h>

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
typedef _STACK STACK;
#endif

struct SslUnsafeErrorEntry {
    int code;
    int depth;

    static SslUnsafeErrorEntry fromStoreContext(X509_STORE_CTX *ctx);
};
Q_DECLARE_TYPEINFO(SslUnsafeErrorEntry, Q_PRIMITIVE_TYPE);

class SslUnsafeSocketBackendPrivate : public SslUnsafeSocketPrivate
{
    Q_DECLARE_PUBLIC(SslUnsafeSocket)
public:
    SslUnsafeSocketBackendPrivate();
    virtual ~SslUnsafeSocketBackendPrivate();

    // SSL context
    bool initSslContext();
    void destroySslContext();
    SSL *ssl;
    BIO *readBio;
    BIO *writeBio;
    SSL_SESSION *session;
    QVector<SslUnsafeErrorEntry> errorList;
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
    static int s_indexForSSLExtraData; // index used in SSL_get_ex_data to get the matching QSslSocketBackendPrivate
#endif

    // Platform specific functions
    void startClientEncryption() Q_DECL_OVERRIDE;
    void startServerEncryption() Q_DECL_OVERRIDE;
    void transmit() Q_DECL_OVERRIDE;
    bool startHandshake();
    void disconnectFromHost() Q_DECL_OVERRIDE;
    void disconnected() Q_DECL_OVERRIDE;
    SslUnsafeCipher sessionCipher() const Q_DECL_OVERRIDE;
    SslUnsafe::SslProtocol sessionProtocol() const Q_DECL_OVERRIDE;
    void continueHandshake() Q_DECL_OVERRIDE;
    bool checkSslErrors();
    void storePeerCertificates();
    unsigned int tlsPskClientCallback(const char *hint, char *identity, unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len);
    unsigned int tlsPskServerCallback(const char *identity, unsigned char *psk, unsigned int max_psk_len);

    static long setupOpenSslOptions(SslUnsafe::SslProtocol protocol, SslUnsafe::SslOptions sslOptions);
    static SslUnsafeCipher SslUnsafeCipher_from_SSL_CIPHER(SSL_CIPHER *cipher);
    static QList<SslUnsafeCertificate> STACKOFX509_to_SslUnsafeCertificates(STACK_OF(X509) *x509);
    static QList<SslUnsafeError> verify(const QList<SslUnsafeCertificate> &certificateChain, const QString &hostName);
    static QString getErrorsFromOpenSsl();
    static bool importPkcs12(QIODevice *device,
                             SslUnsafeKey *key, SslUnsafeCertificate *cert,
                             QList<SslUnsafeCertificate> *caCertificates,
                             const QByteArray &passPhrase);
};

#endif
