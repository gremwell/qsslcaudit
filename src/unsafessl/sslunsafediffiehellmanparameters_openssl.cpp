
#include "sslunsafediffiehellmanparameters.h"
#include "sslunsafediffiehellmanparameters_p.h"
#include "sslunsafesocket_openssl_symbols_p.h"
#include "sslunsafesocket.h"
#include "sslunsafesocket_p.h"

#include <QtCore/qatomic.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qiodevice.h>
#ifndef QT_NO_DEBUG_STREAM
#include <QtCore/qdebug.h>
#endif

// For q_BN_is_word.
#include <openssl/bn.h>

static bool isSafeDH(DH *dh)
{
    int status = 0;
    int bad = 0;

    SslUnsafeSocketPrivate::ensureInitialized();

    // Mark p < 1024 bits as unsafe.
    if (uq_BN_num_bits(dh->p) < 1024) {
        return false;
    }

    if (uq_DH_check(dh, &status) != 1)
        return false;

    // From https://wiki.openssl.org/index.php/Diffie-Hellman_parameters:
    //
    //     The additional call to BN_mod_word(dh->p, 24)
    //     (and unmasking of DH_NOT_SUITABLE_GENERATOR)
    //     is performed to ensure your program accepts
    //     IETF group parameters. OpenSSL checks the prime
    //     is congruent to 11 when g = 2; while the IETF's
    //     primes are congruent to 23 when g = 2.
    //     Without the test, the IETF parameters would
    //     fail validation. For details, see Diffie-Hellman
    //     Parameter Check (when g = 2, must p mod 24 == 11?).
    if (uq_BN_is_word(dh->g, DH_GENERATOR_2)) {
        long residue = uq_BN_mod_word(dh->p, 24);
        if (residue == 11 || residue == 23)
            status &= ~DH_NOT_SUITABLE_GENERATOR;
    }

    bad |= DH_CHECK_P_NOT_PRIME;
    bad |= DH_CHECK_P_NOT_SAFE_PRIME;
    bad |= DH_NOT_SUITABLE_GENERATOR;

    return !(status & bad);
}

void SslUnsafeDiffieHellmanParametersPrivate::decodeDer(const QByteArray &der)
{
    if (der.isEmpty()) {
        error = SslUnsafeDiffieHellmanParameters::InvalidInputDataError;
        return;
    }

    const unsigned char *data = reinterpret_cast<const unsigned char *>(der.data());
    int len = der.size();

    SslUnsafeSocketPrivate::ensureInitialized();

    DH *dh = uq_d2i_DHparams(NULL, &data, len);
    if (dh) {
        if (isSafeDH(dh))
            derData = der;
        else
            error =  SslUnsafeDiffieHellmanParameters::UnsafeParametersError;
    } else {
        error = SslUnsafeDiffieHellmanParameters::InvalidInputDataError;
    }

    uq_DH_free(dh);
}

void SslUnsafeDiffieHellmanParametersPrivate::decodePem(const QByteArray &pem)
{
    if (pem.isEmpty()) {
        error = SslUnsafeDiffieHellmanParameters::InvalidInputDataError;
        return;
    }

    if (!SslUnsafeSocket::supportsSsl()) {
        error = SslUnsafeDiffieHellmanParameters::InvalidInputDataError;
        return;
    }

    SslUnsafeSocketPrivate::ensureInitialized();

    BIO *bio = uq_BIO_new_mem_buf(const_cast<char *>(pem.data()), pem.size());
    if (!bio) {
        error = SslUnsafeDiffieHellmanParameters::InvalidInputDataError;
        return;
    }

    DH *dh = Q_NULLPTR;
    uq_PEM_read_bio_DHparams(bio, &dh, 0, 0);

    if (dh) {
        if (isSafeDH(dh)) {
            char *buf = Q_NULLPTR;
            int len = uq_i2d_DHparams(dh, reinterpret_cast<unsigned char **>(&buf));
            if (len > 0)
                derData = QByteArray(buf, len);
            else
                error = SslUnsafeDiffieHellmanParameters::InvalidInputDataError;
        } else {
            error = SslUnsafeDiffieHellmanParameters::UnsafeParametersError;
        }
    } else {
        error = SslUnsafeDiffieHellmanParameters::InvalidInputDataError;
    }

    uq_DH_free(dh);
    uq_BIO_free(bio);
}
