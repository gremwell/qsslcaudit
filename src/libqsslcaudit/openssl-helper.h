#ifndef OPENSSLHELPER_H
#define OPENSSLHELPER_H

#include <stddef.h>

bool getCertPublicKey(const char *certData, size_t certLen,
                      unsigned char *out, size_t *outLen,
                      bool pem = true);

bool pkcs8PrivKeyToPem(const char *privKeyRaw, size_t privKeyRawLen,
                       char *privKeyPem, size_t maxSize, size_t *privKeyPemLen,
                       bool doSave = true, const char *privKeyFileName = NULL);

bool getCertSerial(const char *certData, size_t certLen,
                   unsigned char *out, size_t maxSize, size_t *outLen,
                   bool pem = true);

bool genSignedCaCertWithSerial(const char *caSerial,
                               const char *privKeyData, size_t privKeyLen,
                               unsigned char *out, size_t maxSize, size_t *outLen,
                               bool doSave = true, const char *certFileName = NULL);

bool genSignedCertForCN(const char *commonName,
                        const char *caCertData, size_t caCertLen,
                        const char *caPrivKeyData, size_t caPrivKeyLen,
                        unsigned char *outKey, size_t maxSizeKey, size_t *outKeyLen,
                        unsigned char *outCert, size_t maxSizeCert, size_t *outCertLen,
                        bool doSave = true,
                        const char *certFileName = NULL, const char *keyFileName = NULL);

#endif // OPENSSLHELPER_H
