#include "mainwindow.h"
#include "./ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setWindowTitle("Транзакции");
    readJson("tranz.json");
    changeTranzs();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_openButton_clicked()
{
    readJson(QFileDialog::getOpenFileName());
    this->ui->tranzListWidget->clear();
    changeTranzs();
}

bool MainWindow::readJson(QString file_name)
{
    QFile jsonFile(file_name);
    jsonFile.open(QFile::ReadOnly);
    QJsonDocument jsonDoc = QJsonDocument::fromJson(jsonFile.readAll());
    m_json_array = jsonDoc.object()["tranzs"].toArray();
    qDebug() << m_json_array;
    for (auto tranz: m_json_array) {
        qDebug() << tranz.toObject()["sum"];
        qDebug() << tranz.toObject()["num"];
        qDebug() << tranz.toObject()["datetime"];
        qDebug() << tranz.toObject()["prev_hash"];
    }
    jsonFile.close();
    return true;
}

void MainWindow::changeTranzs()
{
    this->ui->tranzListWidget->addItem(QString("Сумма") + "\t" + "Номер" + "\t" + "Дата" + "\t\t" + "Хэш предыдущего значения");
    QByteArray prev_hash = QString("1").toUtf8();
    if (prev_hash == QString("1").toUtf8()) {
        qDebug() << "1212";
    }
    qDebug() << prev_hash;
    int cur_row = 1;
    for (auto tranz: m_json_array) {
        QString cur_string_s = tranz.toObject()["sum"].toString() +
                               tranz.toObject()["num"].toString() +
                               tranz.toObject()["datetime"].toString() +
                               tranz.toObject()["prev_hash"].toString();
        this->ui->tranzListWidget->addItem(tranz.toObject()["sum"].toString() +
                                           "\t" + tranz.toObject()["num"].toString() +
                                           "\t" + tranz.toObject()["datetime"].toString() +
                                           "\t" + tranz.toObject()["prev_hash"].toString());
        if (prev_hash == QString("1").toUtf8() || (tranz.toObject()["prev_hash"].toString().toUtf8() == prev_hash.toHex())) {
            qDebug() << "1";
        } else {
            qDebug() << "0";
            this->ui->tranzListWidget->item(cur_row)->setBackground(QBrush(QColor("red")));
        }
        //this->ui->tranzListWidget->currentItem()->setBackground(QBrush(QColor("red")));
        QByteArray cur_hash = tranz.toObject()["prev_hash"].toString().toUtf8();
        qDebug() << cur_hash;
        qDebug() << prev_hash.toHex();
        prev_hash = QCryptographicHash::hash(
            cur_string_s.toUtf8(),
            QCryptographicHash::Sha256);
        cur_row += 1;
    }
}
