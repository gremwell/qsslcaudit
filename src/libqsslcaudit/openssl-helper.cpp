#include "openssl-helper.h"

#include <iostream>
#include <string.h>

#ifdef UNSAFE
#include <openssl-unsafe/bio.h>
#include <openssl-unsafe/x509.h>
#include <openssl-unsafe/evp.h>
#include <openssl-unsafe/pem.h>
#include <openssl-unsafe/x509v3.h>
#else
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#endif


bool getCertPublicKey(const char *certData, size_t certLen,
                      unsigned char *out, size_t *outLen,
                      bool pem)
{
    BIO *bio = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;

    // create an X509 certificate from the provided data
    bio = BIO_new(BIO_s_mem());
    BIO_write(bio, certData, certLen);
    if (pem) {
        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    } else {
        cert = d2i_X509_bio(bio, NULL);
    }
    if (!cert) {
        std::cerr << "can't parse the provided CA certificate" << std::endl;
        return false;
    }

    // extract public key from X509 certificate structure
    pkey = X509_get_pubkey(cert);

    // save raw public key data into the provided buffer
    *outLen = i2d_PUBKEY(pkey, NULL);
    i2d_PUBKEY(pkey, &out);

    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free_all(bio);

    return true;
}

bool pkcs8PrivKeyToPem(const char *privKeyRaw, size_t privKeyRawLen,
                       char *privKeyPem, size_t maxSize, size_t *evilPrivKeyPemLen,
                       bool doSave, const char *privKeyFileName)
{
    BIO *bioIn = NULL;
    BIO *bioOut = NULL;
    BIO *bioF = NULL;
    EVP_PKEY *pkey = NULL;

    // load private key from buffer
    bioIn = BIO_new(BIO_s_mem());
    BIO_write(bioIn, privKeyRaw, privKeyRawLen);
    pkey = d2i_PrivateKey_bio(bioIn, NULL);
    if (!pkey) {
        std::cerr << "can't parse the provided private key" << std::endl;
        return false;
    }

    // save key into memory buffer
    bioOut = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bioOut, pkey, NULL, NULL, 0, NULL, NULL);
    *evilPrivKeyPemLen = BIO_read(bioOut, privKeyPem, maxSize);

    // save private key
    if (doSave) {
        bioF = BIO_new_file(privKeyFileName, "w");
        PEM_write_bio_PrivateKey(bioF, pkey, NULL, NULL, 0, NULL, NULL);
    }

    EVP_PKEY_free(pkey);
    BIO_free_all(bioIn);
    BIO_free_all(bioOut);
    BIO_free_all(bioF);

    return true;
}

bool getCertSerial(const char *certData, size_t certLen,
                   unsigned char *out, size_t maxSize, size_t *outLen,
                   bool pem)
{
    BIO *bio = NULL;
    X509 *cert = NULL;
    ASN1_INTEGER *serial = NULL;
    BIGNUM *bn = NULL;
    char *tmpBuf = NULL;

    // create a certificate from the provided data
    bio = BIO_new(BIO_s_mem());
    BIO_write(bio, certData, certLen);
    if (pem) {
        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    } else {
        cert = d2i_X509_bio(bio, NULL);
    }
    if (!cert) {
        std::cerr << "can't parse the provided certificate" << std::endl;
        return false;
    }

    serial = X509_get_serialNumber(cert);
    if (!serial) {
        std::cerr << "can't obtain certificate' serial number" << std::endl;
        return false;
    }

    bn = ASN1_INTEGER_to_BN(serial, NULL);
    if (!bn) {
        std::cerr << "can't convert serial to big number" << std::endl;
        return false;
    }

    tmpBuf = BN_bn2dec(bn);
    if (!tmpBuf) {
        std::cerr << "can't convert big number to string" << std::endl;
        return false;
    }

    *outLen = strlen(tmpBuf);
    if (*outLen >= maxSize) {
        std::cerr << "not large enough buffer provided" << std::endl;
        return false;
    }

    strncpy((char *)out, tmpBuf, maxSize);

    BN_free(bn);
    X509_free(cert);
    BIO_free_all(bio);

    return true;
}


static int add_ext(X509 *cert, int nid, const char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
    if (!ex)
        return 0;

    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
}

bool genSignedCaCertWithSerial(const char *caSerial,
                               const char *privKeyData, size_t privKeyLen,
                               unsigned char *out, size_t maxSize, size_t *outLen,
                               bool doSave, const char *certFileName)
{
    EVP_PKEY *pkey = NULL;
    BIO *bioPrivKey = NULL;
    BIGNUM *bn = NULL;
    ASN1_INTEGER *asn1serial = NULL;
    BIO *bioOut = NULL;
    BIO *bioFile = NULL;
    X509 *newCert = NULL;
    X509_NAME *name = NULL;
    const EVP_MD *digest = EVP_sha256();
    X509_REQ *req = NULL;

    // import private key from the provided data
    bioPrivKey = BIO_new(BIO_s_mem());
    BIO_write(bioPrivKey, privKeyData, privKeyLen);
    pkey = PEM_read_bio_PrivateKey(bioPrivKey, NULL, NULL, NULL);
    if (!pkey) {
        std::cerr << "can't parse the private key" << std::endl;
        return false;
    }

    // create a new certificate request as a template
    req = X509_REQ_new();
    X509_REQ_set_version(req, 0L);

    name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"BE", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST",  MBSTRING_ASC, (unsigned char *)"Brussels", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"Gremwell", -1, -1, 0);

    X509_REQ_set_pubkey(req, pkey);

    // create a new certificate
    newCert = X509_new();
    X509_set_version(newCert, 2);

    // set serial from the original certificate
    BN_dec2bn(&bn, caSerial);
    asn1serial = BN_to_ASN1_INTEGER(bn, NULL);
    if (!asn1serial) {
        std::cerr << "can't convert the provided serial number" << std::endl;
        return false;
    }
    X509_set_serialNumber(newCert, asn1serial);

    // set issuer and subject as the request's subject
    X509_set_issuer_name(newCert, X509_REQ_get_subject_name(req));
    X509_set_subject_name(newCert, X509_REQ_get_subject_name(req));

    // adjust validity time
    X509_gmtime_adj(X509_get_notBefore(newCert), 0);
    X509_time_adj_ex(X509_get_notAfter(newCert), 30, 0, NULL);

    // set public key as in the request
    X509_set_pubkey(newCert, X509_REQ_get_pubkey(req));

    // add various extensions, this should make our certificate CA-capable
    add_ext(newCert, NID_basic_constraints, "critical,CA:TRUE");
    add_ext(newCert, NID_subject_key_identifier, "hash");
    add_ext(newCert, NID_authority_key_identifier, "keyid:always");

    // sign it using the provided key
    X509_sign(newCert, pkey, digest);

    // save the certificate into memory buffer
    bioOut = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bioOut, newCert);
    *outLen = BIO_read(bioOut, out, maxSize);

    // save the certificate as a file
    if (doSave) {
        bioFile = BIO_new_file(certFileName, "w");
        PEM_write_bio_X509(bioFile, newCert);
    }

    EVP_PKEY_free(pkey);
    X509_free(newCert);
    X509_REQ_free(req);
    BN_free(bn);
    BIO_free_all(bioPrivKey);
    BIO_free_all(bioOut);
    BIO_free_all(bioFile);

    return true;
}

static int rand_serial(BIGNUM *b, ASN1_INTEGER *ai)
{
    BIGNUM *btmp;
    int ret = 0;
    if (b) {
        btmp = b;
    } else {
        btmp = BN_new();
    }
    if (!btmp)
        return 0;
# define SERIAL_RAND_BITS        64
    if (!BN_pseudo_rand(btmp, SERIAL_RAND_BITS, 0, 0))
        goto error;
    if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
        goto error;
    ret = 1;
error:
    if (!b)
        BN_free(btmp);
    return ret;
}

bool genSignedCertForCN(const char *commonName,
                        const char *caCertData, size_t caCertLen,
                        const char *caPrivKeyData, size_t caPrivKeyLen,
                        unsigned char *outKey, size_t maxSizeKey, size_t *outKeyLen,
                        unsigned char *outCert, size_t maxSizeCert, size_t *outCertLen,
                        bool doSave,
                        const char *certFileName, const char *keyFileName)
{
    BIO *bioCa = NULL;
    BIO *bioCaKey = NULL;
    BIO *bioOut = NULL;
    EC_GROUP *ecgroup = NULL;
    EC_KEY *eckey = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *caCert = NULL;
    X509 *newcert = NULL;
    EVP_PKEY *caPrivKey = NULL;
    X509_NAME *name = NULL;
    ASN1_INTEGER *aserial = NULL;
    X509_REQ *certreq = NULL;
    const EVP_MD *digest = EVP_sha256();

    // create an X509 certificate from the provided data
    bioCa = BIO_new(BIO_s_mem());
    BIO_write(bioCa, caCertData, caCertLen);
    caCert = PEM_read_bio_X509(bioCa, NULL, NULL, NULL);
    if (!caCert) {
        std::cerr << "can't parse the provided CA certificate" << std::endl;
        return false;
    }

    // create private key from the provided data
    bioCaKey = BIO_new(BIO_s_mem());
    BIO_write(bioCaKey, caPrivKeyData, caPrivKeyLen);
    caPrivKey = PEM_read_bio_PrivateKey(bioCaKey, NULL, NULL, NULL);
    if (!caPrivKey) {
        std::cerr << "can't parse the provided private key" << std::endl;
        return false;
    }

    // generate a new private key
    ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    eckey = EC_KEY_new();
    EC_GROUP_set_asn1_flag(ecgroup, 1);
    EC_KEY_set_group(eckey, ecgroup);
    EC_KEY_generate_key(eckey);
    pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, eckey);
    if (!pkey) {
        std::cerr << "can't create a new private key" << std::endl;
        return false;
    }

    // create a CSR
    certreq = X509_REQ_new();
    X509_REQ_set_version(certreq, 0L);

    name = X509_REQ_get_subject_name(certreq);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"BE", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"Gremwell", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)commonName, -1, -1, 0);

    X509_REQ_set_pubkey(certreq, pkey);

    X509_REQ_sign(certreq, pkey, digest);

    // build a new certificate
    newcert = X509_new();
    X509_set_version(newcert, 2);

    // set the certificate serial number here
    aserial = ASN1_INTEGER_new();
    rand_serial(NULL, aserial);
    X509_set_serialNumber(newcert, aserial);

    // set the new certificate subject name from signing request
    X509_set_subject_name(newcert, X509_REQ_get_subject_name(certreq));

    // set the new certificate issuer name to CA's subject
    X509_set_issuer_name(newcert, X509_get_subject_name(caCert));

    // set the new certificate public key
    X509_set_pubkey(newcert, X509_REQ_get_pubkey(certreq));

    // adjust validity time
    X509_gmtime_adj(X509_get_notBefore(newcert), 0);
    X509_time_adj_ex(X509_get_notAfter(newcert), 30, 0, NULL);

    // sign the certificate
    X509_sign(newcert, caPrivKey, digest);

    // save the certificate into memory buffer
    bioOut = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bioOut, newcert);
    *outCertLen = BIO_read(bioOut, outCert, maxSizeCert);
    BIO_free_all(bioOut);

    // save the certificate as a file
    if (doSave) {
        bioOut = BIO_new_file(certFileName, "w");
        PEM_write_bio_X509(bioOut, newcert);
        BIO_free_all(bioOut);
    }

    // save the key into memory buffer
    bioOut = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bioOut, pkey, NULL, NULL, 0, NULL, NULL);
    *outKeyLen = BIO_read(bioOut, outKey, maxSizeKey);
    BIO_free_all(bioOut);

    // save the key as a file
    if (doSave) {
        bioOut = BIO_new_file(keyFileName, "w");
        PEM_write_bio_PrivateKey(bioOut, pkey, NULL, NULL, 0, NULL, NULL);
        BIO_free_all(bioOut);
    }

    BIO_free_all(bioCa);
    X509_free(caCert);
    BIO_free_all(bioCaKey);
    EVP_PKEY_free(caPrivKey);
    EVP_PKEY_free(pkey);
    X509_free(newcert);
    X509_REQ_free(certreq);
    ASN1_INTEGER_free(aserial);

    return true;
}
