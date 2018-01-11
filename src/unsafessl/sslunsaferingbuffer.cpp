
#include "sslunsaferingbuffer_p.h"
//#include "private/qbytearray_p.h"
#include <string.h>

const char *SslUnsafeRingBuffer::readPointerAtPosition(qint64 pos, qint64 &length) const
{
    if (pos >= 0) {
        pos += head;
        for (int i = 0; i < buffers.size(); ++i) {
            length = (i == tailBuffer ? tail : buffers[i].size());
            if (length > pos) {
                length -= pos;
                return buffers[i].constData() + pos;
            }
            pos -= length;
        }
    }

    length = 0;
    return 0;
}

void SslUnsafeRingBuffer::free(qint64 bytes)
{
    Q_ASSERT(bytes <= bufferSize);

    while (bytes > 0) {
        const qint64 blockSize = buffers.constFirst().size() - head;

        if (tailBuffer == 0 || blockSize > bytes) {
            // keep a single block around if it does not exceed
            // the basic block size, to avoid repeated allocations
            // between uses of the buffer
            if (bufferSize <= bytes) {
                if (buffers.constFirst().size() <= basicBlockSize) {
                    bufferSize = 0;
                    head = tail = 0;
                } else {
                    clear(); // try to minify/squeeze us
                }
            } else {
                Q_ASSERT(bytes < MaxByteArraySize);
                head += int(bytes);
                bufferSize -= bytes;
            }
            return;
        }

        bufferSize -= blockSize;
        bytes -= blockSize;
        buffers.removeFirst();
        --tailBuffer;
        head = 0;
    }
}

char *SslUnsafeRingBuffer::reserve(qint64 bytes)
{
    if (bytes <= 0 || bytes >= MaxByteArraySize)
        return 0;

    if (bufferSize == 0) {
        if (buffers.isEmpty())
            buffers.append(QByteArray(qMax(basicBlockSize, int(bytes)), Qt::Uninitialized));
        else
            buffers.first().resize(qMax(basicBlockSize, int(bytes)));
    } else {
        const qint64 newSize = bytes + tail;
        // if need a new buffer
        if (basicBlockSize == 0 || (newSize > buffers.constLast().capacity()
                                    && (tail >= basicBlockSize || newSize >= MaxByteArraySize))) {
            // shrink this buffer to its current size
            buffers.last().resize(tail);

            // create a new QByteArray
            buffers.append(QByteArray(qMax(basicBlockSize, int(bytes)), Qt::Uninitialized));
            ++tailBuffer;
            tail = 0;
        } else if (newSize > buffers.constLast().size()) {
            buffers.last().resize(qMax(basicBlockSize, int(newSize)));
        }
    }

    char *writePtr = buffers.last().data() + tail;
    bufferSize += bytes;
    tail += int(bytes);
    return writePtr;
}

/*!
    \internal

    Allocate data at buffer head
*/
char *SslUnsafeRingBuffer::reserveFront(qint64 bytes)
{
    if (bytes <= 0 || bytes >= MaxByteArraySize)
        return 0;

    if (head < bytes || basicBlockSize == 0) {
        if (head > 0) {
            buffers.first().remove(0, head);
            if (tailBuffer == 0)
                tail -= head;
        }

        head = qMax(basicBlockSize, int(bytes));
        if (bufferSize == 0) {
            if (buffers.isEmpty())
                buffers.prepend(QByteArray(head, Qt::Uninitialized));
            else
                buffers.first().resize(head);
            tail = head;
        } else {
            buffers.prepend(QByteArray(head, Qt::Uninitialized));
            ++tailBuffer;
        }
    }

    head -= int(bytes);
    bufferSize += bytes;
    return buffers.first().data() + head;
}

void SslUnsafeRingBuffer::chop(qint64 bytes)
{
    Q_ASSERT(bytes <= bufferSize);

    while (bytes > 0) {
        if (tailBuffer == 0 || tail > bytes) {
            // keep a single block around if it does not exceed
            // the basic block size, to avoid repeated allocations
            // between uses of the buffer
            if (bufferSize <= bytes) {
                if (buffers.constFirst().size() <= basicBlockSize) {
                    bufferSize = 0;
                    head = tail = 0;
                } else {
                    clear(); // try to minify/squeeze us
                }
            } else {
                Q_ASSERT(bytes < MaxByteArraySize);
                tail -= int(bytes);
                bufferSize -= bytes;
            }
            return;
        }

        bufferSize -= tail;
        bytes -= tail;
        buffers.removeLast();
        --tailBuffer;
        tail = buffers.constLast().size();
    }
}

void SslUnsafeRingBuffer::clear()
{
    if (buffers.isEmpty())
        return;

    buffers.erase(buffers.begin() + 1, buffers.end());
    buffers.first().clear();

    head = tail = 0;
    tailBuffer = 0;
    bufferSize = 0;
}

qint64 SslUnsafeRingBuffer::indexOf(char c, qint64 maxLength, qint64 pos) const
{
    if (maxLength <= 0 || pos < 0)
        return -1;

    qint64 index = -(pos + head);
    for (int i = 0; i < buffers.size(); ++i) {
        const qint64 nextBlockIndex = qMin(index + (i == tailBuffer ? tail : buffers[i].size()),
                                           maxLength);

        if (nextBlockIndex > 0) {
            const char *ptr = buffers[i].constData();
            if (index < 0) {
                ptr -= index;
                index = 0;
            }

            const char *findPtr = reinterpret_cast<const char *>(memchr(ptr, c,
                                                                        nextBlockIndex - index));
            if (findPtr)
                return qint64(findPtr - ptr) + index + pos;

            if (nextBlockIndex == maxLength)
                return -1;
        }
        index = nextBlockIndex;
    }
    return -1;
}

qint64 SslUnsafeRingBuffer::read(char *data, qint64 maxLength)
{
    const qint64 bytesToRead = qMin(size(), maxLength);
    qint64 readSoFar = 0;
    while (readSoFar < bytesToRead) {
        const qint64 bytesToReadFromThisBlock = qMin(bytesToRead - readSoFar,
                                                     nextDataBlockSize());
        if (data)
            memcpy(data + readSoFar, readPointer(), bytesToReadFromThisBlock);
        readSoFar += bytesToReadFromThisBlock;
        free(bytesToReadFromThisBlock);
    }
    return readSoFar;
}

/*!
    \internal

    Read an unspecified amount (will read the first buffer)
*/
QByteArray SslUnsafeRingBuffer::read()
{
    if (bufferSize == 0)
        return QByteArray();

    QByteArray qba(buffers.takeFirst());

    qba.reserve(0); // avoid that resizing needlessly reallocates
    if (tailBuffer == 0) {
        qba.resize(tail);
        tail = 0;
    } else {
        --tailBuffer;
    }
    qba.remove(0, head); // does nothing if head is 0
    head = 0;
    bufferSize -= qba.size();
    return qba;
}

/*!
    \internal

    Peek the bytes from a specified position
*/
qint64 SslUnsafeRingBuffer::peek(char *data, qint64 maxLength, qint64 pos) const
{
    qint64 readSoFar = 0;

    if (pos >= 0) {
        pos += head;
        for (int i = 0; readSoFar < maxLength && i < buffers.size(); ++i) {
            qint64 blockLength = (i == tailBuffer ? tail : buffers[i].size());

            if (pos < blockLength) {
                blockLength = qMin(blockLength - pos, maxLength - readSoFar);
                memcpy(data + readSoFar, buffers[i].constData() + pos, blockLength);
                readSoFar += blockLength;
                pos = 0;
            } else {
                pos -= blockLength;
            }
        }
    }

    return readSoFar;
}

/*!
    \internal

    Append bytes from data to the end
*/
void SslUnsafeRingBuffer::append(const char *data, qint64 size)
{
    char *writePointer = reserve(size);
    if (size == 1)
        *writePointer = *data;
    else if (size)
        ::memcpy(writePointer, data, size);
}

/*!
    \internal

    Append a new buffer to the end
*/
void SslUnsafeRingBuffer::append(const QByteArray &qba)
{
    if (tail == 0) {
        if (buffers.isEmpty())
            buffers.append(qba);
        else
            buffers.last() = qba;
    } else {
        buffers.last().resize(tail);
        buffers.append(qba);
        ++tailBuffer;
    }
    tail = qba.size();
    bufferSize += tail;
}

qint64 SslUnsafeRingBuffer::readLine(char *data, qint64 maxLength)
{
    if (!data || --maxLength <= 0)
        return -1;

    qint64 i = indexOf('\n', maxLength);
    i = read(data, i >= 0 ? (i + 1) : maxLength);

    // Terminate it.
    data[i] = '\0';
    return i;
}
