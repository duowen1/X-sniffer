#include "dialog.h"
#include "ui_dialog.h"
#include <QtCharts>
#include <QtCharts/QPieSeries>
#include <QtCharts/QPieSlice>

Dialog::Dialog(QWidget *parent,int ip, int arp) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);

    QPieSlice *slice_1 = new QPieSlice(QStringLiteral("IP数据"), (double)ip/(ip+arp), this);
    slice_1->setLabelVisible(true); // 显示饼状区对应的数据label
    slice_1->setBrush(Qt::green);
    QPieSlice *slice_2 = new QPieSlice(QStringLiteral("ARP数据"), (double)arp/(ip+arp), this);
    slice_2->setLabelVisible(true);
    slice_2->setBrush(Qt::blue);

    // 将两个饼状分区加入series
    QPieSeries *series = new QPieSeries(this);
    series->append(slice_1);
    series->append(slice_2);

    QChart *chart = new QChart();
    chart->addSeries(series);
    chart->setAnimationOptions(QChart::AllAnimations); // 设置显示时的动画效果
    QChartView *chartview = new QChartView(this);
    chartview->show();
    chartview->setChart(chart);
    ui->verticalLayout->insertWidget(0, chartview);
}

Dialog::~Dialog()
{
    delete ui;
}
