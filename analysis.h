#ifndef ANALYSIS_H
#define ANALYSIS_H

#endif // ANALYSIS_H
#include <QThread>
#define HAVE_REMOTE
#include <pcap.h>
#include <gloable.h>

class Analysis:public QThread{
    Q_OBJECT
public:
    Analysis(QObject * parent=0);
protected:
    void run();
signals:
    void PacketRead(QString,QString,QString,QString,QString,QString);
public slots:
    void terminatethread();
private:
    bool flag;
    char *file;
};

Q_DECLARE_METATYPE(pcap_pkthdr);

