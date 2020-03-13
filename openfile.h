#ifndef OPENFILE_H
#define OPENFILE_H
#include <QThread>
#define HAVE_REMOTE
#include <pcap.h>
#include <QTableWidgetItem>
#endif // OPENFILE_H
#include <gloable.h>

class Openfile : public QThread{
    Q_OBJECT
public:
    Openfile(QObject * parent=0, QString str="file.txt");
protected:
    void run();
signals:
    void PacketRead(QString,QString,QString,QString,QString,QString);
private:
    QString filepath;
};


