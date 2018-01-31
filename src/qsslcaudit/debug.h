// thanks to http://brianmilco.blogspot.be/2011/11/color-debug-output-with-qt-and-qdebug.html

#ifndef DEBUG_H
#define DEBUG_H

#include <QDebug>

#define DEBUG(msg) \
( \
    (fprintf(stdout, "%s\n", QString(msg).toLocal8Bit().constData())), \
    (void)0 \
)

#define VERBOSE(msg) \
( \
    (fprintf(stdout, "%s\n", QString(msg).toLocal8Bit().constData())), \
    (void)0 \
)

#define WHITE(msg) \
( \
    (fprintf(stdout, "\033[1m%s\033[0m\n", QString(msg).toLocal8Bit().constData())), \
    (void)0 \
)

#define GREEN(msg) \
( \
    (fprintf(stdout, "\033[1;32m%s\033[0m\n", QString(msg).toLocal8Bit().constData())), \
    (void)0 \
)

#define RED(msg) \
( \
    (fprintf(stdout, "\033[1;31m%s\033[0m\n", QString(msg).toLocal8Bit().constData())), \
    (void)0 \
)

#endif // DEBUG_H
