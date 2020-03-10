#include "mainwindow.h"
#include <QApplication>
#include <gloable.h>
QMutex mutex_in;
QMutex mutex_out;
QMutex mutex_inter;
int main(int argc, char *argv[])
{
    mutex_out.lock();
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}

