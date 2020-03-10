#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include <intercept.h>
#include <analysis.h>
#include <QVariant>

#define RESERVED 0
#define ICMP 1
#define IGMP 2
#define TCP 6
#define UDP 17

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    QString ToString(const int);
    u_short zijiexu(u_short);
    u_int tozijiexu(u_int);

private slots:
    void on_actionexit_triggered();
    void RecordCell(int row,int column);

    void on_pushButton_clicked();
    void UpdateHead(int packet_number,QVariant Vhead_info,char * pkt_data);

    void on_pushButton_2_clicked();

    void on_action_2_triggered();

    void on_TransButton_clicked();

    void on_action_3_triggered();

    void on_pushButton_3_clicked();

    void on_action_4_triggered();

    void on_action_stop_triggered();

    void on_action_start_triggered();

    void on_filter_button_clicked();

signals:
    void stopanalysis();
    void stopintercept();

private:
    Ui::MainWindow *ui;
    Intercept * inter;
    Analysis * anal;
    int row;
    int tcps;
    int udps;
    int ips;
    int arps;
    int icmps;
    int igmps;

};
#endif // MAINWINDOW_H
