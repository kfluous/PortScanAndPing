#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->lineEdit_scanIP_End->hide();
    ui->static_text_scanIP_2->hide();

}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_scanBegin_clicked()
{
    ui->textEdit->clear();

    strtemp=ui->lineEdit_scanIP->text();
    BA_scanIp = strtemp.toLatin1();
    scanIp = BA_scanIp.data();

    strtemp2=ui->lineEdit_scanIP_End->text();
    BA_scanIp2 = strtemp2.toLatin1();
    scanIp_end = BA_scanIp2.data();

    int index = ui->comboBox->currentIndex();

    switch(index){
    case 0:
        startPort=ui->lineEdit_startPort->text().toInt();
        endPort = ui->lineEdit_endPort->text().toInt();

        QObject::connect(&a,SIGNAL(sendMessage(QString)),this,SLOT(reveiveMessage(QString)),Qt::DirectConnection);
        a.tcp_connect(scanIp,startPort,endPort);
        QObject::disconnect(&a,SIGNAL(sendMessage(QString)),this,SLOT(reveiveMessage(QString)));
        break;
    case 1:
        startPort=ui->lineEdit_startPort->text().toInt();
        endPort = ui->lineEdit_endPort->text().toInt();

        QObject::connect(&a,SIGNAL(sendMessage(QString)),this,SLOT(reveiveMessage(QString)));
        a.syn_scan(scanIp,startPort,endPort);
        QObject::disconnect(&a,SIGNAL(sendMessage(QString)),this,SLOT(reveiveMessage(QString)));
        break;
    case 2:
        startPort=ui->lineEdit_startPort->text().toInt();
        endPort = ui->lineEdit_endPort->text().toInt();

        QObject::connect(&a,SIGNAL(sendMessage(QString)),this,SLOT(reveiveMessage(QString)));
        a.fin_scan(scanIp,startPort,endPort);
        QObject::disconnect(&a,SIGNAL(sendMessage(QString)),this,SLOT(reveiveMessage(QString)));
        break;
    case 3:

        QObject::connect(&b,SIGNAL(sendMessage(QString)),this,SLOT(reveiveMessage(QString)));
        b.pinglist(scanIp,scanIp_end,1);
        QObject::disconnect(&b,SIGNAL(sendMessage(QString)),this,SLOT(reveiveMessage(QString)));
        break;
    }

}

void MainWindow::on_lineEdit_scanIP_editingFinished()
{

}

void MainWindow::reveiveMessage(QString msg){

    ui->textEdit->append(msg);
    QApplication::processEvents();

}

void MainWindow::on_pushButton_clicked()
{
    ui->textEdit->clear();
}

void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    if(index!=3){
        ui->lineEdit_scanIP_End->hide();
        ui->static_text_scanIP_2->hide();

        ui->lineEdit_startPort->show();
        ui->lineEdit_endPort->show();
        ui->static_text_startPort->show();
        ui->static_text_endPort->show();

    }else{
        ui->lineEdit_startPort->hide();
        ui->lineEdit_endPort->hide();
        ui->static_text_startPort->hide();
        ui->static_text_endPort->hide();

        ui->lineEdit_scanIP_End->show();
        ui->static_text_scanIP_2->show();



    }
}
