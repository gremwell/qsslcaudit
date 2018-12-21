// thanks to http://brianmilco.blogspot.be/2011/11/color-debug-output-with-qt-and-qdebug.html

#ifndef ERRORHANDLER_H
#define ERRORHANDLER_H

#include <QCoreApplication>

void errorHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg);

#endif // ERRORHANDLER_H
