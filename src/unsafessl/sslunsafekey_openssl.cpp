
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
    if (algorithm == SslUnsafe::Rsa && rsa) {
        if (deep)
            q_RSA_free(rsa);
        rsa = 0;
    }
    if (algorithm == SslUnsafe::Dsa && dsa) {
        if (deep)
            q_DSA_free(dsa);
        dsa = 0;
    }
#ifndef OPENSSL_NO_EC
    if (algorithm == SslUnsafe::Ec && ec) {
       if (deep)
            q_EC_KEY_free(ec);
       ec = 0;
    }
#endif
    if (algorithm == SslUnsafe::Opaque && opaque) {
        if (deep)
            q_EVP_PKEY_free(opaque);
        opaque = 0;
    }
}

bool SslUnsafeKeyPrivate::fromEVP_PKEY(EVP_PKEY *pkey)
{
    if (pkey == nullptr)
        return false;

    if (pkey->type == EVP_PKEY_RSA) {
        isNull = false;
        algorithm = SslUnsafe::Rsa;
        type = SslUnsafe::PrivateKey;

        rsa = q_RSA_new();
        memcpy(rsa, q_EVP_PKEY_get1_RSA(pkey), sizeof(RSA));

        return true;
    }
    else if (pkey->type == EVP_PKEY_DSA) {
        isNull = false;
        algorithm = SslUnsafe::Dsa;
        type = SslUnsafe::PrivateKey;

        dsa = q_DSA_new();
        memcpy(dsa, q_EVP_PKEY_get1_DSA(pkey), sizeof(DSA));

        return true;
    }
#ifndef OPENSSL_NO_EC
    else if (pkey->type == EVP_PKEY_EC) {
        isNull = false;
        algorithm = SslUnsafe::Ec;
        type = SslUnsafe::PrivateKey;
        ec = q_EC_KEY_dup(q_EVP_PKEY_get1_EC_KEY(pkey));

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

    BIO *bio = q_BIO_new_mem_buf(const_cast<char *>(pem.data()), pem.size());
    if (!bio)
        return;

    void *phrase = const_cast<char *>(passPhrase.constData());

    if (algorithm == SslUnsafe::Rsa) {
        RSA *result = (type == SslUnsafe::PublicKey)
            ? q_PEM_read_bio_RSA_PUBKEY(bio, &rsa, 0, phrase)
            : q_PEM_read_bio_RSAPrivateKey(bio, &rsa, 0, phrase);
        if (rsa && rsa == result)
            isNull = false;
    } else if (algorithm == SslUnsafe::Dsa) {
        DSA *result = (type == SslUnsafe::PublicKey)
            ? q_PEM_read_bio_DSA_PUBKEY(bio, &dsa, 0, phrase)
            : q_PEM_read_bio_DSAPrivateKey(bio, &dsa, 0, phrase);
        if (dsa && dsa == result)
            isNull = false;
#ifndef OPENSSL_NO_EC
    } else if (algorithm == SslUnsafe::Ec) {
        EC_KEY *result = (type == SslUnsafe::PublicKey)
            ? q_PEM_read_bio_EC_PUBKEY(bio, &ec, 0, phrase)
            : q_PEM_read_bio_ECPrivateKey(bio, &ec, 0, phrase);
        if (ec && ec == result)
            isNull = false;
#endif
    }

    q_BIO_free(bio);
}

int SslUnsafeKeyPrivate::length() const
{
    if (isNull || algorithm == SslUnsafe::Opaque)
        return -1;

    switch (algorithm) {
        case SslUnsafe::Rsa: return q_BN_num_bits(rsa->n);
        case SslUnsafe::Dsa: return q_BN_num_bits(dsa->p);
#ifndef OPENSSL_NO_EC
        case SslUnsafe::Ec: return q_EC_GROUP_get_degree(q_EC_KEY_get0_group(ec));
#endif
        default: return -1;
    }
}

QByteArray SslUnsafeKeyPrivate::toPem(const QByteArray &passPhrase) const
{
    if (!SslUnsafeSocket::supportsSsl() || isNull || algorithm == SslUnsafe::Opaque)
        return QByteArray();

    BIO *bio = q_BIO_new(q_BIO_s_mem());
    if (!bio)
        return QByteArray();

    bool fail = false;

    if (algorithm == SslUnsafe::Rsa) {
        if (type == SslUnsafe::PublicKey) {
            if (!q_PEM_write_bio_RSA_PUBKEY(bio, rsa))
                fail = true;
        } else {
            if (!q_PEM_write_bio_RSAPrivateKey(
                    bio, rsa,
                    // ### the cipher should be selectable in the API:
                    passPhrase.isEmpty() ? (const EVP_CIPHER *)0 : q_EVP_des_ede3_cbc(),
                    const_cast<uchar *>((const uchar *)passPhrase.data()), passPhrase.size(), 0, 0)) {
                fail = true;
            }
        }
    } else if (algorithm == SslUnsafe::Dsa) {
        if (type == SslUnsafe::PublicKey) {
            if (!q_PEM_write_bio_DSA_PUBKEY(bio, dsa))
                fail = true;
        } else {
            if (!q_PEM_write_bio_DSAPrivateKey(
                    bio, dsa,
                    // ### the cipher should be selectable in the API:
                    passPhrase.isEmpty() ? (const EVP_CIPHER *)0 : q_EVP_des_ede3_cbc(),
                    const_cast<uchar *>((const uchar *)passPhrase.data()), passPhrase.size(), 0, 0)) {
                fail = true;
            }
        }
#ifndef OPENSSL_NO_EC
    } else if (algorithm == SslUnsafe::Ec) {
        if (type == SslUnsafe::PublicKey) {
            if (!q_PEM_write_bio_EC_PUBKEY(bio, ec))
                fail = true;
        } else {
            if (!q_PEM_write_bio_ECPrivateKey(
                    bio, ec,
                    // ### the cipher should be selectable in the API:
                    passPhrase.isEmpty() ? (const EVP_CIPHER *)0 : q_EVP_des_ede3_cbc(),
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
        long size = q_BIO_get_mem_data(bio, &data);
        pem = QByteArray(data, size);
    }
    q_BIO_free(bio);
    return pem;
}

Qt::HANDLE SslUnsafeKeyPrivate::handle() const
{
    switch (algorithm) {
    case SslUnsafe::Opaque:
        return Qt::HANDLE(opaque);
    case SslUnsafe::Rsa:
        return Qt::HANDLE(rsa);
    case SslUnsafe::Dsa:
        return Qt::HANDLE(dsa);
#ifndef OPENSSL_NO_EC
    case SslUnsafe::Ec:
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
        type = q_EVP_des_cbc();
        break;
    case SslUnsafeKeyPrivate::DesEde3Cbc:
        type = q_EVP_des_ede3_cbc();
        break;
    case SslUnsafeKeyPrivate::Rc2Cbc:
        type = q_EVP_rc2_cbc();
        break;
    }

    QByteArray output;
    output.resize(data.size() + EVP_MAX_BLOCK_LENGTH);
    q_EVP_CIPHER_CTX_init(&ctx);
    q_EVP_CipherInit(&ctx, type, NULL, NULL, enc);
    q_EVP_CIPHER_CTX_set_key_length(&ctx, key.size());
    if (cipher == SslUnsafeKeyPrivate::Rc2Cbc)
        q_EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_SET_RC2_KEY_BITS, 8 * key.size(), NULL);
    q_EVP_CipherInit(&ctx, NULL,
        reinterpret_cast<const unsigned char *>(key.constData()),
        reinterpret_cast<const unsigned char *>(iv.constData()), enc);
    q_EVP_CipherUpdate(&ctx,
        reinterpret_cast<unsigned char *>(output.data()), &len,
        reinterpret_cast<const unsigned char *>(data.constData()), data.size());
    q_EVP_CipherFinal(&ctx,
        reinterpret_cast<unsigned char *>(output.data()) + len, &i);
    len += i;
    q_EVP_CIPHER_CTX_cleanup(&ctx);

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
