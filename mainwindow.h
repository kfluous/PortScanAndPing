#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QtWidgets/QTextBrowser>
#include "tcpscan.h"
#include "ping.h"


namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:

    explicit MainWindow(QWidget *parent = 0);
    tcpscan a;
    ping b;
    ~MainWindow();

private slots:
    void on_pushButton_scanBegin_clicked();
    void on_lineEdit_scanIP_editingFinished();
    void reveiveMessage(QString msg);

    void on_pushButton_clicked();

    void on_comboBox_currentIndexChanged(int index);

private:
    Ui::MainWindow *ui;
    const char* scanIp;
    int startPort;
    int endPort;
    const char* scanIp_end;
    QByteArray BA_scanIp;
    QString strtemp;
    QByteArray BA_scanIp2;
    QString strtemp2;
};

#endif // MAINWINDOW_H
