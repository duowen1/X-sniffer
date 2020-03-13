#ifndef INTERCEPT_H
#define INTERCEPT_H

#endif // INTERCEPT_H

#include <QThread>
class Intercept: public QThread{
    Q_OBJECT;
public:
    Intercept(QObject * parent=0,int ada=4,QString str="");
protected:
    void run();
signals:
public slots:
    void terminatethread();
private:
    bool flag;
    int adapter;
    QString filter_str;
};
