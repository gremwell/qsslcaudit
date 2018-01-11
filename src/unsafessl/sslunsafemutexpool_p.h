#ifndef SSLUNSAFEMUTEXPOOL_P_H
#define SSKUNSAFEMUTEXPOOL_P_H

//#include <QtCore/private/qglobal_p.h>
#include "QtCore/qatomic.h"
#include "QtCore/qmutex.h"
#include "QtCore/qvarlengtharray.h"

#ifndef QT_NO_THREAD

class SslUnsafeMutexPool
{
public:
    explicit SslUnsafeMutexPool(QMutex::RecursionMode recursionMode = QMutex::NonRecursive, int size = 131);
    ~SslUnsafeMutexPool();

    inline QMutex *get(const void *address) {
        int index = uint(quintptr(address)) % mutexes.count();
        QMutex *m = mutexes[index].load();
        if (m)
            return m;
        else
            return createMutex(index);
    }
    static SslUnsafeMutexPool *instance();
    static QMutex *globalInstanceGet(const void *address);

private:
    QMutex *createMutex(int index);
    QVarLengthArray<QAtomicPointer<QMutex>, 131> mutexes;
    QMutex::RecursionMode recursionMode;
};

#endif // QT_NO_THREAD

#endif // QMUTEXPOOL_P_H
