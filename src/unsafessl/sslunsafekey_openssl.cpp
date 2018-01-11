
#include "sslunsafekey.h"
#include "sslunsafekey_p.h"
#include "sslunsafesocket_openssl_symbols_p.h"
#include "sslunsafesocket.h"
#include "sslunsafesocket_p.h"

#include <QtCore/qatomic.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qiodevice.h>
#ifndef QT_NO_DEBUG_STREAM
#include <QtCore/qdebug.h>
#endif

QT_BEGIN_NAMESPACE

void SslUnsafeKeyPrivate::clear(bool deep)
{
    isNull = true;
    if (!SslUnsafeSocket::supportsSsl())
        return;
    if (algorithm == QSsl::Rsa && rsa) {
        if (deep)
            uq_RSA_free(rsa);
        rsa = 0;
    }
    if (algorithm == QSsl::Dsa && dsa) {
        if (deep)
            uq_DSA_free(dsa);
        dsa = 0;
    }
#ifndef OPENSSL_NO_EC
    if (algorithm == QSsl::Ec && ec) {
       if (deep)
            uq_EC_KEY_free(ec);
       ec = 0;
    }
#endif
    if (algorithm == QSsl::Opaque && opaque) {
        if (deep)
            uq_EVP_PKEY_free(opaque);
        opaque = 0;
    }
}

bool SslUnsafeKeyPrivate::fromEVP_PKEY(EVP_PKEY *pkey)
{
    if (pkey == nullptr)
        return false;

    if (pkey->type == EVP_PKEY_RSA) {
        isNull = false;
        algorithm = QSsl::Rsa;
        type = QSsl::PrivateKey;

        rsa = uq_RSA_new();
        memcpy(rsa, uq_EVP_PKEY_get1_RSA(pkey), sizeof(RSA));

        return true;
    }
    else if (pkey->type == EVP_PKEY_DSA) {
        isNull = false;
        algorithm = QSsl::Dsa;
        type = QSsl::PrivateKey;

        dsa = uq_DSA_new();
        memcpy(dsa, uq_EVP_PKEY_get1_DSA(pkey), sizeof(DSA));

        return true;
    }
#ifndef OPENSSL_NO_EC
    else if (pkey->type == EVP_PKEY_EC) {
        isNull = false;
        algorithm = QSsl::Ec;
        type = QSsl::PrivateKey;
        ec = uq_EC_KEY_dup(uq_EVP_PKEY_get1_EC_KEY(pkey));

        return true;
    }
#endif
    else {
        // Unknown key type. This could be handled as opaque, but then
        // we'd eventually leak memory since we wouldn't be able to free
        // the underlying EVP_PKEY structure. For now, we won't support
        // this.
    }

    return false;
}

void SslUnsafeKeyPrivate::decodeDer(const QByteArray &der, bool deepClear)
{
    QMap<QByteArray, QByteArray> headers;
    decodePem(pemFromDer(der, headers), QByteArray(), deepClear);
}

void SslUnsafeKeyPrivate::decodePem(const QByteArray &pem, const QByteArray &passPhrase,
                               bool deepClear)
{
    if (pem.isEmpty())
        return;

    clear(deepClear);

    if (!SslUnsafeSocket::supportsSsl())
        return;

    BIO *bio = uq_BIO_new_mem_buf(const_cast<char *>(pem.data()), pem.size());
    if (!bio)
        return;

    void *phrase = const_cast<char *>(passPhrase.constData());

    if (algorithm == QSsl::Rsa) {
        RSA *result = (type == QSsl::PublicKey)
            ? uq_PEM_read_bio_RSA_PUBKEY(bio, &rsa, 0, phrase)
            : uq_PEM_read_bio_RSAPrivateKey(bio, &rsa, 0, phrase);
        if (rsa && rsa == result)
            isNull = false;
    } else if (algorithm == QSsl::Dsa) {
        DSA *result = (type == QSsl::PublicKey)
            ? uq_PEM_read_bio_DSA_PUBKEY(bio, &dsa, 0, phrase)
            : uq_PEM_read_bio_DSAPrivateKey(bio, &dsa, 0, phrase);
        if (dsa && dsa == result)
            isNull = false;
#ifndef OPENSSL_NO_EC
    } else if (algorithm == QSsl::Ec) {
        EC_KEY *result = (type == QSsl::PublicKey)
            ? uq_PEM_read_bio_EC_PUBKEY(bio, &ec, 0, phrase)
            : uq_PEM_read_bio_ECPrivateKey(bio, &ec, 0, phrase);
        if (ec && ec == result)
            isNull = false;
#endif
    }

    uq_BIO_free(bio);
}

int SslUnsafeKeyPrivate::length() const
{
    if (isNull || algorithm == QSsl::Opaque)
        return -1;

    switch (algorithm) {
        case QSsl::Rsa: return uq_BN_num_bits(rsa->n);
        case QSsl::Dsa: return uq_BN_num_bits(dsa->p);
#ifndef OPENSSL_NO_EC
        case QSsl::Ec: return uq_EC_GROUP_get_degree(uq_EC_KEY_get0_group(ec));
#endif
        default: return -1;
    }
}

QByteArray SslUnsafeKeyPrivate::toPem(const QByteArray &passPhrase) const
{
    if (!SslUnsafeSocket::supportsSsl() || isNull || algorithm == QSsl::Opaque)
        return QByteArray();

    BIO *bio = uq_BIO_new(uq_BIO_s_mem());
    if (!bio)
        return QByteArray();

    bool fail = false;

    if (algorithm == QSsl::Rsa) {
        if (type == QSsl::PublicKey) {
            if (!uq_PEM_write_bio_RSA_PUBKEY(bio, rsa))
                fail = true;
        } else {
            if (!uq_PEM_write_bio_RSAPrivateKey(
                    bio, rsa,
                    // ### the cipher should be selectable in the API:
                    passPhrase.isEmpty() ? (const EVP_CIPHER *)0 : uq_EVP_des_ede3_cbc(),
                    const_cast<uchar *>((const uchar *)passPhrase.data()), passPhrase.size(), 0, 0)) {
                fail = true;
            }
        }
    } else if (algorithm == QSsl::Dsa) {
        if (type == QSsl::PublicKey) {
            if (!uq_PEM_write_bio_DSA_PUBKEY(bio, dsa))
                fail = true;
        } else {
            if (!uq_PEM_write_bio_DSAPrivateKey(
                    bio, dsa,
                    // ### the cipher should be selectable in the API:
                    passPhrase.isEmpty() ? (const EVP_CIPHER *)0 : uq_EVP_des_ede3_cbc(),
                    const_cast<uchar *>((const uchar *)passPhrase.data()), passPhrase.size(), 0, 0)) {
                fail = true;
            }
        }
#ifndef OPENSSL_NO_EC
    } else if (algorithm == QSsl::Ec) {
        if (type == QSsl::PublicKey) {
            if (!uq_PEM_write_bio_EC_PUBKEY(bio, ec))
                fail = true;
        } else {
            if (!uq_PEM_write_bio_ECPrivateKey(
                    bio, ec,
                    // ### the cipher should be selectable in the API:
                    passPhrase.isEmpty() ? (const EVP_CIPHER *)0 : uq_EVP_des_ede3_cbc(),
                    const_cast<uchar *>((const uchar *)passPhrase.data()), passPhrase.size(), 0, 0)) {
                fail = true;
            }
        }
#endif
    } else {
        fail = true;
    }

    QByteArray pem;
    if (!fail) {
        char *data;
        long size = uq_BIO_get_mem_data(bio, &data);
        pem = QByteArray(data, size);
    }
    uq_BIO_free(bio);
    return pem;
}

Qt::HANDLE SslUnsafeKeyPrivate::handle() const
{
    switch (algorithm) {
    case QSsl::Opaque:
        return Qt::HANDLE(opaque);
    case QSsl::Rsa:
        return Qt::HANDLE(rsa);
    case QSsl::Dsa:
        return Qt::HANDLE(dsa);
#ifndef OPENSSL_NO_EC
    case QSsl::Ec:
        return Qt::HANDLE(ec);
#endif
    default:
        return Qt::HANDLE(NULL);
    }
}

static QByteArray doCrypt(SslUnsafeKeyPrivate::Cipher cipher, const QByteArray &data, const QByteArray &key, const QByteArray &iv, int enc)
{
    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER* type = 0;
    int i = 0, len = 0;

    switch (cipher) {
    case SslUnsafeKeyPrivate::DesCbc:
        type = uq_EVP_des_cbc();
        break;
    case SslUnsafeKeyPrivate::DesEde3Cbc:
        type = uq_EVP_des_ede3_cbc();
        break;
    case SslUnsafeKeyPrivate::Rc2Cbc:
        type = uq_EVP_rc2_cbc();
        break;
    }

    QByteArray output;
    output.resize(data.size() + EVP_MAX_BLOCK_LENGTH);
    uq_EVP_CIPHER_CTX_init(&ctx);
    uq_EVP_CipherInit(&ctx, type, NULL, NULL, enc);
    uq_EVP_CIPHER_CTX_set_key_length(&ctx, key.size());
    if (cipher == SslUnsafeKeyPrivate::Rc2Cbc)
        uq_EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_SET_RC2_KEY_BITS, 8 * key.size(), NULL);
    uq_EVP_CipherInit(&ctx, NULL,
        reinterpret_cast<const unsigned char *>(key.constData()),
        reinterpret_cast<const unsigned char *>(iv.constData()), enc);
    uq_EVP_CipherUpdate(&ctx,
        reinterpret_cast<unsigned char *>(output.data()), &len,
        reinterpret_cast<const unsigned char *>(data.constData()), data.size());
    uq_EVP_CipherFinal(&ctx,
        reinterpret_cast<unsigned char *>(output.data()) + len, &i);
    len += i;
    uq_EVP_CIPHER_CTX_cleanup(&ctx);

    return output.left(len);
}

QByteArray SslUnsafeKeyPrivate::decrypt(Cipher cipher, const QByteArray &data, const QByteArray &key, const QByteArray &iv)
{
    return doCrypt(cipher, data, key, iv, 0);
}

QByteArray SslUnsafeKeyPrivate::encrypt(Cipher cipher, const QByteArray &data, const QByteArray &key, const QByteArray &iv)
{
    return doCrypt(cipher, data, key, iv, 1);
}
