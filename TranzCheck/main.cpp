#include "mainwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    // Главная функция вызывает конструктор основного окна
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
