#include "mainwindow.h"
#include "./ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setWindowTitle("Транзакции");
    ReadJson();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_openButton_clicked()
{

}

bool MainWindow::ReadJson()
{
    QFile jsonFile("tranz.json");
    jsonFile.open(QFile::ReadOnly);
    QJsonDocument jsonDoc = QJsonDocument::fromJson(jsonFile.readAll());
    m_json_array = jsonDoc.object()["tranzs"].toArray();
    for (auto tranz: m_json_array) {
        qDebug() << tranz.toObject()["sum"];
        qDebug() << tranz.toObject()["num"];
        qDebug() << tranz.toObject()["datetime"];
        qDebug() << tranz.toObject()["prev_hash"];
    }
    jsonFile.close();
    return true;
}

