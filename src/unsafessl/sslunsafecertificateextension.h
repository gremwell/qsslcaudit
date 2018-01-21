#ifndef SSLUNSAFECERTIFICATEEXTENSION_H
#define SSLUNSAFECERTIFICATEEXTENSION_H

//#include <QtNetwork/qtnetworkglobal.h>
#include <QtCore/qnamespace.h>
#include <QtCore/qshareddata.h>
#include <QtCore/qstring.h>
#include <QtCore/qvariant.h>

#ifndef QT_NO_SSL

class SslUnsafeCertificateExtensionPrivate;

class SslUnsafeCertificateExtension
{
public:
    SslUnsafeCertificateExtension();
    SslUnsafeCertificateExtension(const SslUnsafeCertificateExtension &other);
#ifdef Q_COMPILER_RVALUE_REFS
    SslUnsafeCertificateExtension &operator=(SslUnsafeCertificateExtension &&other) Q_DECL_NOTHROW { swap(other); return *this; }
#endif
    SslUnsafeCertificateExtension &operator=(const SslUnsafeCertificateExtension &other);
    ~SslUnsafeCertificateExtension();

    void swap(SslUnsafeCertificateExtension &other) Q_DECL_NOTHROW { qSwap(d, other.d); }

    QString oid() const;
    QString name() const;
    QVariant value() const;
    bool isCritical() const;

    bool isSupported() const;

private:
    friend class SslUnsafeCertificatePrivate;
    QSharedDataPointer<SslUnsafeCertificateExtensionPrivate> d;
};

Q_DECLARE_SHARED(SslUnsafeCertificateExtension)

#endif // QT_NO_SSL

#endif // SslUnsafeCertificateExtension_H
