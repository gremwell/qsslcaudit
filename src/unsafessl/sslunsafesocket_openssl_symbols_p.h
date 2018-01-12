#ifndef SSLUNSAFESOCKET_OPENSSL_SYMBOLS_P_H
#define SSLUNSAFESOCKET_OPENSSL_SYMBOLS_P_H

//#include <QtNetwork/private/qtnetworkglobal_p.h>
#include "sslunsafesocket_openssl_p.h"
#include <QtCore/qglobal.h>

#define DUMMYARG

// **************** Shared declarations ******************
// ret func(arg)

#  define DEFINEFUNC(ret, func, arg, a, err, funcret) \
    typedef ret (*_uq_PTR_##func)(arg); \
    static _uq_PTR_##func _uq_##func = 0; \
    ret uq_##func(arg) { \
        if (Q_UNLIKELY(!_uq_##func)) { \
            sslUnsafeSocketUnresolvedSymbolWarning(#func); \
            err; \
        } \
        funcret _uq_##func(a); \
    }

// ret func(arg1, arg2)
#  define DEFINEFUNC2(ret, func, arg1, a, arg2, b, err, funcret) \
    typedef ret (*_uq_PTR_##func)(arg1, arg2);         \
    static _uq_PTR_##func _uq_##func = 0;               \
    ret uq_##func(arg1, arg2) { \
        if (Q_UNLIKELY(!_uq_##func)) { \
            sslUnsafeSocketUnresolvedSymbolWarning(#func);\
            err; \
        } \
        funcret _uq_##func(a, b); \
    }

// ret func(arg1, arg2, arg3)
#  define DEFINEFUNC3(ret, func, arg1, a, arg2, b, arg3, c, err, funcret) \
    typedef ret (*_uq_PTR_##func)(arg1, arg2, arg3);            \
    static _uq_PTR_##func _uq_##func = 0;                        \
    ret uq_##func(arg1, arg2, arg3) { \
        if (Q_UNLIKELY(!_uq_##func)) { \
            sslUnsafeSocketUnresolvedSymbolWarning(#func); \
            err; \
        } \
        funcret _uq_##func(a, b, c); \
    }

// ret func(arg1, arg2, arg3, arg4)
#  define DEFINEFUNC4(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, err, funcret) \
    typedef ret (*_uq_PTR_##func)(arg1, arg2, arg3, arg4);               \
    static _uq_PTR_##func _uq_##func = 0;                                 \
    ret uq_##func(arg1, arg2, arg3, arg4) { \
         if (Q_UNLIKELY(!_uq_##func)) { \
             sslUnsafeSocketUnresolvedSymbolWarning(#func); \
             err; \
         } \
         funcret _uq_##func(a, b, c, d); \
    }

// ret func(arg1, arg2, arg3, arg4, arg5)
#  define DEFINEFUNC5(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, err, funcret) \
    typedef ret (*_uq_PTR_##func)(arg1, arg2, arg3, arg4, arg5);         \
    static _uq_PTR_##func _uq_##func = 0;                                 \
    ret uq_##func(arg1, arg2, arg3, arg4, arg5) { \
        if (Q_UNLIKELY(!_uq_##func)) { \
            sslUnsafeSocketUnresolvedSymbolWarning(#func); \
            err; \
        } \
        funcret _uq_##func(a, b, c, d, e); \
    }

// ret func(arg1, arg2, arg3, arg4, arg6)
#  define DEFINEFUNC6(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, arg6, f, err, funcret) \
    typedef ret (*_uq_PTR_##func)(arg1, arg2, arg3, arg4, arg5, arg6);   \
    static _uq_PTR_##func _uq_##func = 0;                                 \
    ret uq_##func(arg1, arg2, arg3, arg4, arg5, arg6) { \
        if (Q_UNLIKELY(!_uq_##func)) { \
            sslUnsafeSocketUnresolvedSymbolWarning(#func); \
            err; \
        } \
        funcret _uq_##func(a, b, c, d, e, f); \
    }

// ret func(arg1, arg2, arg3, arg4, arg6, arg7)
#  define DEFINEFUNC7(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, arg6, f, arg7, g, err, funcret) \
    typedef ret (*_uq_PTR_##func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7);   \
    static _uq_PTR_##func _uq_##func = 0;                                       \
    ret uq_##func(arg1, arg2, arg3, arg4, arg5, arg6, arg7) { \
        if (Q_UNLIKELY(!_uq_##func)) { \
            sslUnsafeSocketUnresolvedSymbolWarning(#func); \
            err; \
        } \
        funcret _uq_##func(a, b, c, d, e, f, g); \
    }

// ret func(arg1, arg2, arg3, arg4, arg6, arg7, arg8, arg9)
#  define DEFINEFUNC9(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, arg6, f, arg7, g, arg8, h, arg9, i, err, funcret) \
    typedef ret (*_uq_PTR_##func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);   \
    static _uq_PTR_##func _uq_##func = 0;                                                   \
    ret uq_##func(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) { \
        if (Q_UNLIKELY(!_uq_##func)) { \
            sslUnsafeSocketUnresolvedSymbolWarning(#func); \
            err; \
        }   \
        funcret _uq_##func(a, b, c, d, e, f, g, h, i); \
    }
// **************** Shared declarations ******************


bool uq_resolveOpenSslSymbols();
long uq_ASN1_INTEGER_get(ASN1_INTEGER *a);
unsigned char * uq_ASN1_STRING_data(ASN1_STRING *a);
int uq_ASN1_STRING_length(ASN1_STRING *a);
int uq_ASN1_STRING_to_UTF8(unsigned char **a, ASN1_STRING *b);
long uq_BIO_ctrl(BIO *a, int b, long c, void *d);
Q_AUTOTEST_EXPORT int uq_BIO_free(BIO *a);
Q_AUTOTEST_EXPORT BIO *uq_BIO_new(BIO_METHOD *a);
BIO *uq_BIO_new_mem_buf(void *a, int b);
int uq_BIO_read(BIO *a, void *b, int c);
Q_AUTOTEST_EXPORT BIO_METHOD *uq_BIO_s_mem();
Q_AUTOTEST_EXPORT int uq_BIO_write(BIO *a, const void *b, int c);
BIGNUM * uq_BN_new();
int uq_BN_num_bits(const BIGNUM *a);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
int uq_BN_is_word(BIGNUM *a, BN_ULONG w);
#else
// BN_is_word is implemented purely as a
// macro in OpenSSL < 1.1. It doesn't
// call any functions.
//
// The implementation of BN_is_word is
// 100% the same between 1.0.0, 1.0.1
// and 1.0.2.
//
// Users are required to include <openssl/bn.h>.
#define uq_BN_is_word BN_is_word
#endif // OPENSSL_VERSION_NUMBER >= 0x10100000L
BN_ULONG uq_BN_mod_word(const BIGNUM *a, BN_ULONG w);
int uq_BN_set_word(const BIGNUM *a, BN_ULONG w);
void uq_BN_free(BIGNUM *a);
#ifndef OPENSSL_NO_EC
const EC_GROUP* uq_EC_KEY_get0_group(const EC_KEY* k);
int uq_EC_GROUP_get_degree(const EC_GROUP* g);
#endif
int uq_CRYPTO_num_locks();
void uq_CRYPTO_set_locking_callback(void (*a)(int, int, const char *, int));
void uq_CRYPTO_set_id_callback(unsigned long (*a)());
void uq_CRYPTO_free(void *a);
DSA *uq_DSA_new();
void uq_DSA_free(DSA *a);
X509 *uq_d2i_X509(X509 **a, const unsigned char **b, long c);
char *uq_ERR_error_string(unsigned long a, char *b);
unsigned long uq_ERR_get_error();
void uq_ERR_free_strings();
void uq_EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a);
void uq_EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
int uq_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int uq_EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
int uq_EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv, int enc);
int uq_EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
int uq_EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
const EVP_CIPHER *uq_EVP_des_cbc();
const EVP_CIPHER *uq_EVP_des_ede3_cbc();
const EVP_CIPHER *uq_EVP_rc2_cbc();
int uq_EVP_PKEY_assign(EVP_PKEY *a, int b, char *c);
int uq_EVP_PKEY_set1_RSA(EVP_PKEY *a, RSA *b);
int uq_EVP_PKEY_set1_DSA(EVP_PKEY *a, DSA *b);
#ifndef OPENSSL_NO_EC
int uq_EVP_PKEY_set1_EC_KEY(EVP_PKEY *a, EC_KEY *b);
#endif
void uq_EVP_PKEY_free(EVP_PKEY *a);
RSA *uq_EVP_PKEY_get1_RSA(EVP_PKEY *a);
DSA *uq_EVP_PKEY_get1_DSA(EVP_PKEY *a);
#ifndef OPENSSL_NO_EC
EC_KEY *uq_EVP_PKEY_get1_EC_KEY(EVP_PKEY *a);
#endif
int uq_EVP_PKEY_type(int a);
EVP_PKEY *uq_EVP_PKEY_new();
int uq_i2d_X509(X509 *a, unsigned char **b);
const char *uq_OBJ_nid2sn(int a);
const char *uq_OBJ_nid2ln(int a);
int uq_OBJ_sn2nid(const char *s);
int uq_OBJ_ln2nid(const char *s);
int uq_i2t_ASN1_OBJECT(char *buf, int buf_len, ASN1_OBJECT *obj);
int uq_OBJ_obj2txt(char *buf, int buf_len, ASN1_OBJECT *obj, int no_name);
int uq_OBJ_obj2nid(const ASN1_OBJECT *a);
#ifdef SSLEAY_MACROS
// ### verify
void *uq_PEM_ASN1_read_bio(d2i_of_void *a, const char *b, BIO *c, void **d, pem_password_cb *e,
                          void *f);
// ### ditto for write
#else
EVP_PKEY *uq_PEM_read_bio_PrivateKey(BIO *a, EVP_PKEY **b, pem_password_cb *c, void *d);
DSA *uq_PEM_read_bio_DSAPrivateKey(BIO *a, DSA **b, pem_password_cb *c, void *d);
RSA *uq_PEM_read_bio_RSAPrivateKey(BIO *a, RSA **b, pem_password_cb *c, void *d);
#ifndef OPENSSL_NO_EC
EC_KEY *uq_PEM_read_bio_ECPrivateKey(BIO *a, EC_KEY **b, pem_password_cb *c, void *d);
#endif
DH *uq_PEM_read_bio_DHparams(BIO *a, DH **b, pem_password_cb *c, void *d);
int uq_PEM_write_bio_DSAPrivateKey(BIO *a, DSA *b, const EVP_CIPHER *c, unsigned char *d,
                                  int e, pem_password_cb *f, void *g);
int uq_PEM_write_bio_RSAPrivateKey(BIO *a, RSA *b, const EVP_CIPHER *c, unsigned char *d,
                                  int e, pem_password_cb *f, void *g);
#ifndef OPENSSL_NO_EC
int uq_PEM_write_bio_ECPrivateKey(BIO *a, EC_KEY *b, const EVP_CIPHER *c, unsigned char *d,
                                  int e, pem_password_cb *f, void *g);
#endif
#endif
EVP_PKEY *uq_PEM_read_bio_PUBKEY(BIO *a, EVP_PKEY **b, pem_password_cb *c, void *d);
DSA *uq_PEM_read_bio_DSA_PUBKEY(BIO *a, DSA **b, pem_password_cb *c, void *d);
RSA *uq_PEM_read_bio_RSA_PUBKEY(BIO *a, RSA **b, pem_password_cb *c, void *d);
#ifndef OPENSSL_NO_EC
EC_KEY *uq_PEM_read_bio_EC_PUBKEY(BIO *a, EC_KEY **b, pem_password_cb *c, void *d);
#endif
int uq_PEM_write_bio_DSA_PUBKEY(BIO *a, DSA *b);
int uq_PEM_write_bio_RSA_PUBKEY(BIO *a, RSA *b);
#ifndef OPENSSL_NO_EC
int uq_PEM_write_bio_EC_PUBKEY(BIO *a, EC_KEY *b);
#endif
void uq_RAND_seed(const void *a, int b);
int uq_RAND_status();
RSA *uq_RSA_new();
void uq_RSA_free(RSA *a);
int uq_RSA_generate_key_ex(RSA *a, int bits, BIGNUM *e, BN_GENCB *cb);
int uq_sk_num(STACK *a);
void uq_sk_pop_free(STACK *a, void (*b)(void *));
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
_STACK *uq_sk_new_null();
void uq_sk_push(_STACK *st, void *data);
void uq_sk_free(_STACK *a);
void * uq_sk_value(STACK *a, int b);
#else
STACK *uq_sk_new_null();
void uq_sk_push(STACK *st, char *data);
void uq_sk_free(STACK *a);
char * uq_sk_value(STACK *a, int b);
#endif
int uq_SSL_accept(SSL *a);
int uq_SSL_clear(SSL *a);
char *uq_SSL_CIPHER_description(SSL_CIPHER *a, char *b, int c);
int uq_SSL_CIPHER_get_bits(SSL_CIPHER *a, int *b);
int uq_SSL_connect(SSL *a);
int uq_SSL_CTX_check_private_key(const SSL_CTX *a);
long uq_SSL_CTX_ctrl(SSL_CTX *a, int b, long c, void *d);
void uq_SSL_CTX_free(SSL_CTX *a);
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
SSL_CTX *uq_SSL_CTX_new(const SSL_METHOD *a);
#else
SSL_CTX *uq_SSL_CTX_new(SSL_METHOD *a);
#endif
int uq_SSL_CTX_set_cipher_list(SSL_CTX *a, const char *b);
int uq_SSL_CTX_set_default_verify_paths(SSL_CTX *a);
void uq_SSL_CTX_set_verify(SSL_CTX *a, int b, int (*c)(int, X509_STORE_CTX *));
void uq_SSL_CTX_set_verify_depth(SSL_CTX *a, int b);
int uq_SSL_CTX_use_certificate(SSL_CTX *a, X509 *b);
int uq_SSL_CTX_use_certificate_file(SSL_CTX *a, const char *b, int c);
int uq_SSL_CTX_use_PrivateKey(SSL_CTX *a, EVP_PKEY *b);
int uq_SSL_CTX_use_RSAPrivateKey(SSL_CTX *a, RSA *b);
int uq_SSL_CTX_use_PrivateKey_file(SSL_CTX *a, const char *b, int c);
X509_STORE *uq_SSL_CTX_get_cert_store(const SSL_CTX *a);
void uq_SSL_free(SSL *a);
STACK_OF(SSL_CIPHER) *uq_SSL_get_ciphers(const SSL *a);
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
const SSL_CIPHER *uq_SSL_get_current_cipher(SSL *a);
#else
SSL_CIPHER *q_SSL_get_current_cipher(SSL *a);
#endif
int uq_SSL_version(const SSL *a);
int uq_SSL_get_error(SSL *a, int b);
STACK_OF(X509) *uq_SSL_get_peer_cert_chain(SSL *a);
X509 *uq_SSL_get_peer_certificate(SSL *a);
long uq_SSL_get_verify_result(const SSL *a);
int uq_SSL_library_init();
void uq_SSL_load_error_strings();
SSL *uq_SSL_new(SSL_CTX *a);
long uq_SSL_ctrl(SSL *ssl,int cmd, long larg, void *parg);
int uq_SSL_read(SSL *a, void *b, int c);
void uq_SSL_set_bio(SSL *a, BIO *b, BIO *c);
void uq_SSL_set_accept_state(SSL *a);
void uq_SSL_set_connect_state(SSL *a);
int uq_SSL_shutdown(SSL *a);
int uq_SSL_set_session(SSL *to, SSL_SESSION *session);
void uq_SSL_SESSION_free(SSL_SESSION *ses);
SSL_SESSION *uq_SSL_get1_session(SSL *ssl);
SSL_SESSION *uq_SSL_get_session(const SSL *ssl);
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
int uq_SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int uq_SSL_set_ex_data(SSL *ssl, int idx, void *arg);
void *uq_SSL_get_ex_data(const SSL *ssl, int idx);
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10001000L && !defined(OPENSSL_NO_PSK)
typedef unsigned int (*uq_psk_client_callback_t)(SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len);
void uq_SSL_set_psk_client_callback(SSL *ssl, uq_psk_client_callback_t callback);
typedef unsigned int (*uq_psk_server_callback_t)(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len);
void uq_SSL_set_psk_server_callback(SSL *ssl, uq_psk_server_callback_t callback);
int uq_SSL_CTX_use_psk_identity_hint(SSL_CTX *ctx, const char *hint);
#endif // OPENSSL_VERSION_NUMBER >= 0x10001000L && !defined(OPENSSL_NO_PSK)
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#ifndef OPENSSL_NO_SSL2
const SSL_METHOD *uq_SSLv2_client_method();
#endif
#ifndef OPENSSL_NO_SSL3_METHOD
const SSL_METHOD *uq_SSLv3_client_method();
#endif
const SSL_METHOD *uq_SSLv23_client_method();
const SSL_METHOD *uq_TLSv1_client_method();
const SSL_METHOD *uq_TLSv1_1_client_method();
const SSL_METHOD *uq_TLSv1_2_client_method();
#ifndef OPENSSL_NO_SSL2
const SSL_METHOD *uq_SSLv2_server_method();
#endif
#ifndef OPENSSL_NO_SSL3_METHOD
const SSL_METHOD *uq_SSLv3_server_method();
#endif
const SSL_METHOD *uq_SSLv23_server_method();
const SSL_METHOD *uq_TLSv1_server_method();
const SSL_METHOD *uq_TLSv1_1_server_method();
const SSL_METHOD *uq_TLSv1_2_server_method();
#else
#ifndef OPENSSL_NO_SSL2
SSL_METHOD *uq_SSLv2_client_method();
#endif
#ifndef OPENSSL_NO_SSL3_METHOD
SSL_METHOD *uq_SSLv3_client_method();
#endif
SSL_METHOD *uq_SSLv23_client_method();
SSL_METHOD *uq_TLSv1_client_method();
SSL_METHOD *uq_TLSv1_1_client_method();
SSL_METHOD *uq_TLSv1_2_client_method();
#ifndef OPENSSL_NO_SSL2
SSL_METHOD *uq_SSLv2_server_method();
#endif
#ifndef OPENSSL_NO_SSL3_METHOD
SSL_METHOD *uq_SSLv3_server_method();
#endif
SSL_METHOD *uq_SSLv23_server_method();
SSL_METHOD *uq_TLSv1_server_method();
SSL_METHOD *uq_TLSv1_1_server_method();
SSL_METHOD *uq_TLSv1_2_server_method();
#endif
int uq_SSL_write(SSL *a, const void *b, int c);
int uq_X509_cmp(X509 *a, X509 *b);
#ifdef SSLEAY_MACROS
void *uq_ASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, char *x);
#define uq_X509_dup(x509) (X509 *)q_ASN1_dup((i2d_of_void *)q_i2d_X509, \
                (d2i_of_void *)q_d2i_X509,(char *)x509)
#else
X509 *uq_X509_dup(X509 *a);
#endif
void uq_X509_print(BIO *a, X509*b);
ASN1_OBJECT *uq_X509_EXTENSION_get_object(X509_EXTENSION *a);
void uq_X509_free(X509 *a);
X509_EXTENSION *uq_X509_get_ext(X509 *a, int b);
int uq_X509_get_ext_count(X509 *a);
void *uq_X509_get_ext_d2i(X509 *a, int b, int *c, int *d);
const X509V3_EXT_METHOD *uq_X509V3_EXT_get(X509_EXTENSION *a);
void *uq_X509V3_EXT_d2i(X509_EXTENSION *a);
int uq_X509_EXTENSION_get_critical(X509_EXTENSION *a);
ASN1_OCTET_STRING *uq_X509_EXTENSION_get_data(X509_EXTENSION *a);
void uq_BASIC_CONSTRAINTS_free(BASIC_CONSTRAINTS *a);
void uq_AUTHORITY_KEYID_free(AUTHORITY_KEYID *a);
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
int uq_ASN1_STRING_print(BIO *a, const ASN1_STRING *b);
#else
int uq_ASN1_STRING_print(BIO *a, ASN1_STRING *b);
#endif
int uq_X509_check_issued(X509 *a, X509 *b);
X509_NAME *uq_X509_get_issuer_name(X509 *a);
X509_NAME *uq_X509_get_subject_name(X509 *a);
int uq_X509_verify_cert(X509_STORE_CTX *ctx);
int uq_X509_NAME_entry_count(X509_NAME *a);
X509_NAME_ENTRY *uq_X509_NAME_get_entry(X509_NAME *a,int b);
ASN1_STRING *uq_X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *a);
ASN1_OBJECT *uq_X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *a);
EVP_PKEY *uq_X509_PUBKEY_get(X509_PUBKEY *a);
void uq_X509_STORE_free(X509_STORE *store);
X509_STORE *uq_X509_STORE_new();
int uq_X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
void uq_X509_STORE_CTX_free(X509_STORE_CTX *storeCtx);
int uq_X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store,
                          X509 *x509, STACK_OF(X509) *chain);
X509_STORE_CTX *uq_X509_STORE_CTX_new();
int uq_X509_STORE_CTX_set_purpose(X509_STORE_CTX *ctx, int purpose);
int uq_X509_STORE_CTX_get_error(X509_STORE_CTX *ctx);
int uq_X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx);
X509 *uq_X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx);
STACK_OF(X509) *uq_X509_STORE_CTX_get_chain(X509_STORE_CTX *ctx);

// Diffie-Hellman support
DH *uq_DH_new();
void uq_DH_free(DH *dh);
DH *uq_d2i_DHparams(DH **a, const unsigned char **pp, long length);
int uq_i2d_DHparams(DH *a, unsigned char **p);
int uq_DH_check(DH *dh, int *codes);

BIGNUM *uq_BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
#define uq_SSL_CTX_set_tmp_dh(ctx, dh) uq_SSL_CTX_ctrl((ctx), SSL_CTRL_SET_TMP_DH, 0, (char *)dh)
#define uq_SSL_CTX_set_tmp_rsa(ctx, rsa) uq_SSL_CTX_ctrl((ctx), SSL_CTRL_SET_TMP_RSA, 0, (char *)rsa)

#ifndef OPENSSL_NO_EC
// EC Diffie-Hellman support
EC_KEY *uq_EC_KEY_dup(const EC_KEY *src);
EC_KEY *uq_EC_KEY_new_by_curve_name(int nid);
void uq_EC_KEY_free(EC_KEY *ecdh);
#define uq_SSL_CTX_set_tmp_ecdh(ctx, ecdh) uq_SSL_CTX_ctrl((ctx), SSL_CTRL_SET_TMP_ECDH, 0, (char *)ecdh)

// EC curves management
size_t uq_EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
int uq_EC_curve_nist2nid(const char *name);
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
#endif // OPENSSL_NO_EC
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
#define q_SSL_get_server_tmp_key(ssl, key) uq_SSL_ctrl((ssl), SSL_CTRL_GET_SERVER_TMP_KEY, 0, (char *)key)
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

// PKCS#12 support
int uq_PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca);
PKCS12 *uq_d2i_PKCS12_bio(BIO *bio, PKCS12 **pkcs12);
void uq_PKCS12_free(PKCS12 *pkcs12);


#define uq_BIO_get_mem_data(b, pp) (int)uq_BIO_ctrl(b,BIO_CTRL_INFO,0,(char *)pp)
#define uq_BIO_pending(b) (int)uq_BIO_ctrl(b,BIO_CTRL_PENDING,0,NULL)
#ifdef SSLEAY_MACROS
int     uq_i2d_DSAPrivateKey(const DSA *a, unsigned char **pp);
int     uq_i2d_RSAPrivateKey(const RSA *a, unsigned char **pp);
RSA *uq_d2i_RSAPrivateKey(RSA **a, unsigned char **pp, long length);
DSA *uq_d2i_DSAPrivateKey(DSA **a, unsigned char **pp, long length);
#define uq_PEM_read_bio_RSAPrivateKey(bp, x, cb, u) \
        (RSA *)uq_PEM_ASN1_read_bio( \
        (void *(*)(void**, const unsigned char**, long int))uq_d2i_RSAPrivateKey, PEM_STRING_RSA, bp, (void **)x, cb, u)
#define uq_PEM_read_bio_DSAPrivateKey(bp, x, cb, u) \
        (DSA *)uq_PEM_ASN1_read_bio( \
        (void *(*)(void**, const unsigned char**, long int))uq_d2i_DSAPrivateKey, PEM_STRING_DSA, bp, (void **)x, cb, u)
#define uq_PEM_write_bio_RSAPrivateKey(bp,x,enc,kstr,klen,cb,u) \
        PEM_ASN1_write_bio((int (*)(void*, unsigned char**))uq_i2d_RSAPrivateKey,PEM_STRING_RSA,\
                           bp,(char *)x,enc,kstr,klen,cb,u)
#define uq_PEM_write_bio_DSAPrivateKey(bp,x,enc,kstr,klen,cb,u) \
        PEM_ASN1_write_bio((int (*)(void*, unsigned char**))uq_i2d_DSAPrivateKey,PEM_STRING_DSA,\
                           bp,(char *)x,enc,kstr,klen,cb,u)
#define uq_PEM_read_bio_DHparams(bp, dh, cb, u) \
        (DH *)q_PEM_ASN1_read_bio( \
        (void *(*)(void**, const unsigned char**, long int))uq_d2i_DHparams, PEM_STRING_DHPARAMS, bp, (void **)x, cb, u)
#endif
#define uq_SSL_CTX_set_options(ctx,op) uq_SSL_CTX_ctrl((ctx),SSL_CTRL_OPTIONS,(op),NULL)
#define uq_SSL_CTX_set_mode(ctx,op) uq_SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,(op),NULL)
#define uq_SKM_sk_num(type, st) ((int (*)(const STACK_OF(type) *))uq_sk_num)(st)
#define uq_SKM_sk_value(type, st,i) ((type * (*)(const STACK_OF(type) *, int))uq_sk_value)(st, i)
#define uq_sk_GENERAL_NAME_num(st) uq_SKM_sk_num(GENERAL_NAME, (st))
#define uq_sk_GENERAL_NAME_value(st, i) uq_SKM_sk_value(GENERAL_NAME, (st), (i))
#define uq_sk_X509_num(st) uq_SKM_sk_num(X509, (st))
#define uq_sk_X509_value(st, i) uq_SKM_sk_value(X509, (st), (i))
#define uq_sk_SSL_CIPHER_num(st) uq_SKM_sk_num(SSL_CIPHER, (st))
#define uq_sk_SSL_CIPHER_value(st, i) uq_SKM_sk_value(SSL_CIPHER, (st), (i))
#define uq_SSL_CTX_add_extra_chain_cert(ctx,x509) \
        uq_SSL_CTX_ctrl(ctx,SSL_CTRL_EXTRA_CHAIN_CERT,0,(char *)x509)
#define uq_X509_get_notAfter(x) X509_get_notAfter(x)
#define uq_X509_get_notBefore(x) X509_get_notBefore(x)
#define uq_EVP_PKEY_assign_RSA(pkey,rsa) uq_EVP_PKEY_assign((pkey),EVP_PKEY_RSA,\
                                        (char *)(rsa))
#define uq_EVP_PKEY_assign_DSA(pkey,dsa) uq_EVP_PKEY_assign((pkey),EVP_PKEY_DSA,\
                                        (char *)(dsa))
#define uq_OpenSSL_add_all_algorithms() uq_OPENSSL_add_all_algorithms_conf()
void uq_OPENSSL_add_all_algorithms_noconf();
void uq_OPENSSL_add_all_algorithms_conf();
int uq_SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath);
long uq_SSLeay();
const char *uq_SSLeay_version(int type);
int uq_i2d_SSL_SESSION(SSL_SESSION *in, unsigned char **pp);
SSL_SESSION *uq_d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp, long length);

#if OPENSSL_VERSION_NUMBER >= 0x1000100fL && !defined(OPENSSL_NO_NEXTPROTONEG)
int uq_SSL_select_next_proto(unsigned char **out, unsigned char *outlen,
                            const unsigned char *in, unsigned int inlen,
                            const unsigned char *client, unsigned int client_len);
void uq_SSL_CTX_set_next_proto_select_cb(SSL_CTX *s,
                                        int (*cb) (SSL *ssl, unsigned char **out,
                                                   unsigned char *outlen,
                                                   const unsigned char *in,
                                                   unsigned int inlen, void *arg),
                                        void *arg);
void uq_SSL_get0_next_proto_negotiated(const SSL *s, const unsigned char **data,
                                      unsigned *len);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
int uq_SSL_set_alpn_protos(SSL *ssl, const unsigned char *protos,
                          unsigned protos_len);
void uq_SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx,
                                  int (*cb) (SSL *ssl,
                                             const unsigned char **out,
                                             unsigned char *outlen,
                                             const unsigned char *in,
                                             unsigned int inlen,
                                             void *arg), void *arg);
void uq_SSL_get0_alpn_selected(const SSL *ssl, const unsigned char **data,
                              unsigned *len);
#endif
#endif // OPENSSL_VERSION_NUMBER >= 0x1000100fL ...

// Helper function
class QDateTime;
QDateTime uq_getTimeFromASN1(const ASN1_TIME *aTime);

#endif
