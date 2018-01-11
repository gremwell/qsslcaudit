
#include "qatomic.h"
#include "sslunsafemutexpool_p.h"

#ifndef QT_NO_THREAD

Q_GLOBAL_STATIC_WITH_ARGS(SslUnsafeMutexPool, globalMutexPool, (QMutex::Recursive))

/*!
    \class SslUnsafeMutexPool
    \inmodule QtCore
    \brief The SslUnsafeMutexPool class provides a pool of QMutex objects.

    \internal

    \ingroup thread

    SslUnsafeMutexPool is a convenience class that provides access to a fixed
    number of QMutex objects.

    Typical use of a SslUnsafeMutexPool is in situations where it is not
    possible or feasible to use one QMutex for every protected object.
    The mutex pool will return a mutex based on the address of the
    object that needs protection.

    For example, consider this simple class:

    \snippet code/src_corelib_thread_SslUnsafeMutexPool.cpp 0

    Adding a QMutex member to the Number class does not make sense,
    because it is so small. However, in order to ensure that access to
    each Number is protected, you need to use a mutex. In this case, a
    SslUnsafeMutexPool would be ideal.

    Code to calculate the square of a number would then look something
    like this:

    \snippet code/src_corelib_thread_SslUnsafeMutexPool.cpp 1

    This function will safely calculate the square of a number, since
    it uses a mutex from a SslUnsafeMutexPool. The mutex is locked and
    unlocked automatically by the QMutexLocker class. See the
    QMutexLocker documentation for more details.
*/

/*!
    Constructs  a SslUnsafeMutexPool, reserving space for \a size QMutexes. All
    mutexes in the pool are created with \a recursionMode. By default,
    all mutexes are non-recursive.

    The QMutexes are created when needed, and deleted when the
    SslUnsafeMutexPool is destructed.
*/
SslUnsafeMutexPool::SslUnsafeMutexPool(QMutex::RecursionMode recursionMode, int size)
    : mutexes(size), recursionMode(recursionMode)
{
    for (int index = 0; index < mutexes.count(); ++index) {
        mutexes[index].store(0);
    }
}

/*!
    Destructs a SslUnsafeMutexPool. All QMutexes that were created by the pool
    are deleted.
*/
SslUnsafeMutexPool::~SslUnsafeMutexPool()
{
    for (int index = 0; index < mutexes.count(); ++index)
        delete mutexes[index].load();
}

/*!
    Returns the global SslUnsafeMutexPool instance.
*/
SslUnsafeMutexPool *SslUnsafeMutexPool::instance()
{
    return globalMutexPool();
}

/*!
    \fn SslUnsafeMutexPool::get(const void *address)
    Returns a QMutex from the pool. SslUnsafeMutexPool uses the value \a address
    to determine which mutex is returned from the pool.
*/

/*!
    \internal
  create the mutex for the given index
 */
QMutex *SslUnsafeMutexPool::createMutex(int index)
{
    // mutex not created, create one
    QMutex *newMutex = new QMutex(recursionMode);
    if (!mutexes[index].testAndSetRelease(0, newMutex))
        delete newMutex;
    return mutexes[index].load();
}

/*!
    Returns a QMutex from the global mutex pool.
*/
QMutex *SslUnsafeMutexPool::globalInstanceGet(const void *address)
{
    SslUnsafeMutexPool * const globalInstance = globalMutexPool();
    if (globalInstance == 0)
        return 0;
    return globalInstance->get(address);
}

#endif // QT_NO_THREAD
