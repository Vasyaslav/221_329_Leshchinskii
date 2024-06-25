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

bool MainWindow::readJson(QString file_name)
{
    QFile jsonFile(file_name);
    jsonFile.open(QFile::ReadOnly);
    if (!jsonFile.isOpen())
        return false;

    QByteArray hexEcryptedBytes = jsonFile.readAll();
    QByteArray encryptedBytes = QByteArray::fromHex(hexEcryptedBytes);
    QByteArray decryptedBytes;
    // key - SHA256(1234)
    QByteArray aes256_key = QCryptographicHash::hash(
        pin.toUtf8(),
        QCryptographicHash::Sha256);
    int ret_code = decryptByteArray(aes256_key, encryptedBytes, decryptedBytes);
    if (!ret_code)
        return false;

    QJsonParseError p_jsonErr;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(decryptedBytes, &p_jsonErr);
    if (p_jsonErr.error != QJsonParseError::NoError)
        return false;
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

int MainWindow::decryptByteArray(
    const QByteArray & aes256_key,
    const QByteArray &encryptedBytes,
    QByteArray &decryptedBytes
    )
{
    // Функция для QByteArray
    // https://cryptii.com/pipes/aes-encryption
    // key: 03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4
    // iv:  3d3f9cebdd87fbe2c76f1adf8d761208
    // QByteArray key_hex("03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4");
    // QByteArray key_ba = QByteArray::fromHex(key_hex);
    // unsigned char key[32] = {0};
    // memcpy(key, key_ba.data(), 32);

    unsigned char key[32] = {0};
    memcpy(key, aes256_key.data(), 32);

    QByteArray iv_hex("3d3f9cebdd87fbe2c76f1adf8d761208");
    QByteArray iv_ba = QByteArray::fromHex(iv_hex);
    unsigned char iv[16] = {0};
    memcpy(iv, iv_ba.data(), 16);

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex2(ctx, EVP_aes_256_cbc(), key, iv, NULL)) {
        qDebug() << "*** DecryptInit Error ";
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    const int buffer_len = 256;
    unsigned char enc_buffer[buffer_len] = {0};
    unsigned char dec_buffer[buffer_len] = {0};
    int enc_len, dec_len;
    QDataStream enc_stream(encryptedBytes);
    QDataStream dec_stream(&decryptedBytes, QIODevice::ReadWrite);
    enc_len = enc_stream.readRawData(reinterpret_cast<char*>(enc_buffer), buffer_len);
    while (enc_len > 0) {
        if (!EVP_DecryptUpdate(ctx, dec_buffer, &dec_len, enc_buffer, enc_len)) {
            qDebug() << "*** DecryptUpdate Error ";
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        dec_stream.writeRawData(reinterpret_cast<char*>(dec_buffer), dec_len);
        enc_len = enc_stream.readRawData(reinterpret_cast<char*>(enc_buffer), buffer_len);
    }
    if (!EVP_DecryptFinal_ex(ctx, dec_buffer, &dec_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    dec_stream.writeRawData(reinterpret_cast<char*>(dec_buffer), dec_len);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}


int MainWindow::encryptByteArray(
    const QByteArray & aes256_key,
    const QByteArray &encryptedBytes,
    QByteArray &decryptedBytes
    )
{
    // Функция для QByteArray
    // https://cryptii.com/pipes/aes-encryption
    // key: 03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4
    // iv:  3d3f9cebdd87fbe2c76f1adf8d761208
    // QByteArray key_hex("03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4");
    // QByteArray key_ba = QByteArray::fromHex(key_hex);
    // unsigned char key[32] = {0};
    // memcpy(key, key_ba.data(), 32);

    unsigned char key[32] = {0};
    memcpy(key, aes256_key.data(), 32);

    QByteArray iv_hex("3d3f9cebdd87fbe2c76f1adf8d761208");
    QByteArray iv_ba = QByteArray::fromHex(iv_hex);
    unsigned char iv[16] = {0};
    memcpy(iv, iv_ba.data(), 16);

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex2(ctx, EVP_aes_256_cbc(), key, iv, NULL)) {
        qDebug() << "*** EncryptInit Error ";
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    const int buffer_len = 256;
    unsigned char enc_buffer[buffer_len] = {0};
    unsigned char dec_buffer[buffer_len] = {0};
    int enc_len, dec_len;
    QDataStream enc_stream(encryptedBytes);
    QDataStream dec_stream(&decryptedBytes, QIODevice::ReadWrite);
    enc_len = enc_stream.readRawData(reinterpret_cast<char*>(enc_buffer), buffer_len);
    while (enc_len > 0) {
        if (!EVP_EncryptUpdate(ctx, dec_buffer, &dec_len, enc_buffer, enc_len)) {
            qDebug() << "*** EncryptUpdate Error ";
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        dec_stream.writeRawData(reinterpret_cast<char*>(dec_buffer), dec_len);
        enc_len = enc_stream.readRawData(reinterpret_cast<char*>(enc_buffer), buffer_len);
    }
    if (!EVP_EncryptFinal_ex(ctx, dec_buffer, &dec_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    dec_stream.writeRawData(reinterpret_cast<char*>(dec_buffer), dec_len);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

void MainWindow::on_changeKeyButton_clicked()
{
    pin = this->ui->newKEYEdit->text();
}

void MainWindow::on_openButton_clicked()
{
    readJson(QFileDialog::getOpenFileName());
    this->ui->tranzListWidget->clear();
    changeTranzs();
}
