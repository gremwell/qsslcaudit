#ifndef SSLUNSAFEELLIPTICCURVE_H
#define SSLUNSAFEELLIPTICCURVE_H

#include <QtNetwork/qtnetworkglobal.h>
#include <QtCore/QString>
#include <QtCore/QMetaType>
#if QT_DEPRECATED_SINCE(5, 6)
#include <QtCore/QHash>
#endif
#include <QtCore/qhashfunctions.h>


class SslUnsafeEllipticCurve;
// qHash is a friend, but we can't use default arguments for friends (§8.3.6.4)
Q_DECL_CONSTEXPR uint qHash(SslUnsafeEllipticCurve curve, uint seed = 0) Q_DECL_NOTHROW;

class SslUnsafeEllipticCurve {
public:
    Q_DECL_CONSTEXPR SslUnsafeEllipticCurve() Q_DECL_NOTHROW
        : id(0)
    {
    }

    static SslUnsafeEllipticCurve fromShortName(const QString &name);
    static SslUnsafeEllipticCurve fromLongName(const QString &name);

    Q_REQUIRED_RESULT Q_NETWORK_EXPORT QString shortName() const;
    Q_REQUIRED_RESULT Q_NETWORK_EXPORT QString longName() const;

    Q_DECL_CONSTEXPR bool isValid() const Q_DECL_NOTHROW
    {
        return id != 0;
    }

    Q_NETWORK_EXPORT bool isTlsNamedCurve() const Q_DECL_NOTHROW;

private:
    int id;

    friend Q_DECL_CONSTEXPR bool operator==(SslUnsafeEllipticCurve lhs, SslUnsafeEllipticCurve rhs) Q_DECL_NOTHROW;
    friend Q_DECL_CONSTEXPR uint qHash(SslUnsafeEllipticCurve curve, uint seed) Q_DECL_NOTHROW;

    friend class SslUnsafeSocketPrivate;
    friend class SslUnsafeSocketBackendPrivate;
};

Q_DECLARE_TYPEINFO(SslUnsafeEllipticCurve, Q_PRIMITIVE_TYPE);

Q_DECL_CONSTEXPR inline uint qHash(SslUnsafeEllipticCurve curve, uint seed) Q_DECL_NOTHROW
{ return qHash(curve.id, seed); }

Q_DECL_CONSTEXPR inline bool operator==(SslUnsafeEllipticCurve lhs, SslUnsafeEllipticCurve rhs) Q_DECL_NOTHROW
{ return lhs.id == rhs.id; }

Q_DECL_CONSTEXPR inline bool operator!=(SslUnsafeEllipticCurve lhs, SslUnsafeEllipticCurve rhs) Q_DECL_NOTHROW
{ return !operator==(lhs, rhs); }

#ifndef QT_NO_DEBUG_STREAM
class QDebug;
QDebug operator<<(QDebug debug, SslUnsafeEllipticCurve curve);
#endif

Q_DECLARE_METATYPE(SslUnsafeEllipticCurve)

#endif // SslUnsafeEllipticCurve_H
