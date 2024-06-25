#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QColor>
#include <QBrush>
#include <QListWidgetItem>
#include <QFileDialog>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QDebug>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <QCryptographicHash>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_openButton_clicked();

private:
    Ui::MainWindow *ui;
    QJsonArray m_json_array;

    bool readJson(QString file_name);
    void encryptByteArray(const unsigned char* tranz, unsigned char cur_hash[65]);
    void changeTranzs();
};
#endif // MAINWINDOW_H
