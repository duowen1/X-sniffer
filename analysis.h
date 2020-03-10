#ifndef ANALYSIS_H
#define ANALYSIS_H

#endif // ANALYSIS_H
#include <QThread>
#define HAVE_REMOTE
#include <pcap.h>
#include <QVariant>

class Analysis:public QThread{
    Q_OBJECT;
public:
    Analysis(QObject * parent=0);
protected:
    void run();
signals:
    void HeadInformation(int packet_number,QVariant Vheadinfo,char *packet);
public slots:
    void terminatethread();
private:
    bool flag;
};

Q_DECLARE_METATYPE(pcap_pkthdr);
