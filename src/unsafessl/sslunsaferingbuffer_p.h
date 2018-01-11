#ifndef SSLUNSAFERINGBUFFER_P_H
#define SSLUNSAFERINGBUFFER_P_H

//#include <QtCore/private/qglobal_p.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qlist.h>

#ifndef QRINGBUFFER_CHUNKSIZE
#define QRINGBUFFER_CHUNKSIZE 4096
#endif

class SslUnsafeRingBuffer
{
public:
    explicit inline SslUnsafeRingBuffer(int growth = QRINGBUFFER_CHUNKSIZE) :
        head(0), tail(0), tailBuffer(0), basicBlockSize(growth), bufferSize(0) { }

    inline void setChunkSize(int size) {
        basicBlockSize = size;
    }

    inline int chunkSize() const {
        return basicBlockSize;
    }

    inline qint64 nextDataBlockSize() const {
        return (tailBuffer == 0 ? tail : buffers.first().size()) - head;
    }

    inline const char *readPointer() const {
        return bufferSize == 0 ? Q_NULLPTR : (buffers.first().constData() + head);
    }

    const char *readPointerAtPosition(qint64 pos, qint64 &length) const;
    void free(qint64 bytes);
    char *reserve(qint64 bytes);
    char *reserveFront(qint64 bytes);

    inline void truncate(qint64 pos) {
        if (pos < size())
            chop(size() - pos);
    }

    void chop(qint64 bytes);

    inline bool isEmpty() const {
        return bufferSize == 0;
    }

    inline int getChar() {
        if (isEmpty())
            return -1;
        char c = *readPointer();
        free(1);
        return int(uchar(c));
    }

    inline void putChar(char c) {
        char *ptr = reserve(1);
        *ptr = c;
    }

    void ungetChar(char c)
    {
        if (head > 0) {
            --head;
            buffers.first()[head] = c;
            ++bufferSize;
        } else {
            char *ptr = reserveFront(1);
            *ptr = c;
        }
    }


    inline qint64 size() const {
        return bufferSize;
    }

    void clear();
    inline qint64 indexOf(char c) const { return indexOf(c, size()); }
    qint64 indexOf(char c, qint64 maxLength, qint64 pos = 0) const;
    qint64 read(char *data, qint64 maxLength);
    QByteArray read();
    qint64 peek(char *data, qint64 maxLength, qint64 pos = 0) const;
    void append(const char *data, qint64 size);
    void append(const QByteArray &qba);

    inline qint64 skip(qint64 length) {
        qint64 bytesToSkip = qMin(length, bufferSize);

        free(bytesToSkip);
        return bytesToSkip;
    }

    qint64 readLine(char *data, qint64 maxLength);

    inline bool canReadLine() const {
        return indexOf('\n') >= 0;
    }

private:
    enum {
        // Define as enum to force inlining. Don't expose MaxAllocSize in a public header.
        MaxByteArraySize = INT_MAX - sizeof(std::remove_pointer<QByteArray::DataPtr>::type)
    };

    QList<QByteArray> buffers;
    int head, tail;
    int tailBuffer; // always buffers.size() - 1
    int basicBlockSize;
    qint64 bufferSize;
};

#endif // QRINGBUFFER_P_H
