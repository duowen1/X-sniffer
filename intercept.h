#ifndef INTERCEPT_H
#define INTERCEPT_H

#endif // INTERCEPT_H

#include <QThread>
class Intercept: public QThread{
    Q_OBJECT;
public:
    Intercept(QObject * parent=0);
protected:
    void run();
signals:
public slots:
    void terminatethread();
private:
    bool flag;
};
