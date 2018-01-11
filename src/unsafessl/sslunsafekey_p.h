
#ifndef SSLUNSAFEKEY_OPENSSL_P_H
#define SSLUNSAFEKEY_OPENSSL_P_H

//#include <QtNetwork/private/qtnetworkglobal_p.h>
#include "sslunsafekey.h"
#include "sslunsafesocket_p.h" // includes wincrypt.h

#ifndef QT_NO_OPENSSL
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#endif

class SslUnsafeKeyPrivate
{
public:
    inline SslUnsafeKeyPrivate()
        : algorithm(QSsl::Opaque)
        , opaque(0)
    {
        clear(false);
    }

    inline ~SslUnsafeKeyPrivate()
    { clear(); }

    void clear(bool deep = true);

#ifndef QT_NO_OPENSSL
    bool fromEVP_PKEY(EVP_PKEY *pkey);
#endif
    void decodeDer(const QByteArray &der, bool deepClear = true);
    void decodePem(const QByteArray &pem, const QByteArray &passPhrase,
                   bool deepClear = true);
    QByteArray pemHeader() const;
    QByteArray pemFooter() const;
    QByteArray pemFromDer(const QByteArray &der, const QMap<QByteArray, QByteArray> &headers) const;
    QByteArray derFromPem(const QByteArray &pem, QMap<QByteArray, QByteArray> *headers) const;

    int length() const;
    QByteArray toPem(const QByteArray &passPhrase) const;
    Qt::HANDLE handle() const;

    bool isNull;
    QSsl::KeyType type;
    QSsl::KeyAlgorithm algorithm;

    enum Cipher {
        DesCbc,
        DesEde3Cbc,
        Rc2Cbc
    };

    Q_AUTOTEST_EXPORT static QByteArray decrypt(Cipher cipher, const QByteArray &data, const QByteArray &key, const QByteArray &iv);
    Q_AUTOTEST_EXPORT static QByteArray encrypt(Cipher cipher, const QByteArray &data, const QByteArray &key, const QByteArray &iv);

#ifndef QT_NO_OPENSSL
    union {
        EVP_PKEY *opaque;
        RSA *rsa;
        DSA *dsa;
#ifndef OPENSSL_NO_EC
        EC_KEY *ec;
#endif
    };
#else
    Qt::HANDLE opaque;
    QByteArray derData;
    int keyLength;
#endif

    QAtomicInt ref;

private:
    Q_DISABLE_COPY(SslUnsafeKeyPrivate)
};

#endif // QSSLKEY_OPENSSL_P_H
