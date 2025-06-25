#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#include <QJsonDocument>
#include <QJsonObject>
#include <QObject>
#include <crypto/aes.h>
#include <crypto/aes192.h>
#include <crypto/aes256.h>
#include <helper/convert.h>

namespace model {
namespace helper = YanLib::helper;
namespace crypto = YanLib::crypto;

struct ReqAesEncode {
    std::vector<uint8_t> input_text;
    QString mode;
    QString padding;
    QString key_bits;
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
    QString output_encoding;
    static std::pair<bool, ReqAesEncode> from_json(const QJsonObject &obj) {
        ReqAesEncode aes = {};
        if (!obj.contains("inputText") || !obj.contains("aesMode") ||
            !obj.contains("padding") || !obj.contains("keyBits") ||
            !obj.contains("key") || !obj.contains("iv") ||
            !obj.contains("outputEncoding")) {
            return std::make_pair(false, aes);
        }
        auto temp = obj["inputText"].toString().toStdString();
        aes.input_text.assign(temp.begin(), temp.end());

        aes.mode = obj["aesMode"].toString();
        aes.padding = obj["padding"].toString();
        aes.key_bits = obj["keyBits"].toString();

        temp = obj["key"].toString().toStdString();
        aes.key.assign(temp.begin(), temp.end());

        temp = obj["iv"].toString().toStdString();
        aes.iv.assign(temp.begin(), temp.end());
        aes.output_encoding = obj["outputEncoding"].toString();
        return std::make_pair(true, aes);
    }
};

struct ReqAesDecode {
    std::vector<uint8_t> input_text;
    QString mode;
    QString padding;
    QString key_bits;
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
    QString output_encoding;
    static std::pair<bool, ReqAesDecode> from_json(const QJsonObject &obj) {
        ReqAesDecode aes = {};
        if (!obj.contains("inputText") || !obj.contains("aesMode") ||
            !obj.contains("padding") || !obj.contains("keyBits") ||
            !obj.contains("key") || !obj.contains("iv") ||
            !obj.contains("outputEncoding")) {
            return std::make_pair(false, aes);
        }

        aes.mode = obj["aesMode"].toString();
        aes.padding = obj["padding"].toString();
        aes.key_bits = obj["keyBits"].toString();

        auto temp = obj["key"].toString().toStdString();
        aes.key.assign(temp.begin(), temp.end());

        temp = obj["iv"].toString().toStdString();
        aes.iv.assign(temp.begin(), temp.end());

        aes.output_encoding = obj["outputEncoding"].toString();

        auto bytes_temp = obj["inputText"].toString().toUtf8();
        if (aes.output_encoding == "Base64") {
            temp = QByteArray::fromBase64(bytes_temp).toStdString();
        } else if (aes.output_encoding == "Hex") {
            temp = QByteArray::fromHex(bytes_temp).toStdString();
        }
        aes.input_text.assign(temp.begin(), temp.end());
        return std::make_pair(true, aes);
    }
};

class rijndael : public QObject {
    Q_OBJECT
private:
    std::vector<uint8_t> aes128_crypt(const ReqAesEncode &req);

    std::vector<uint8_t> aes128_decrypt(const ReqAesDecode &req);

    std::vector<uint8_t> aes192_crypt(const ReqAesEncode &req);

    std::vector<uint8_t> aes192_decrypt(const ReqAesDecode &req);

    std::vector<uint8_t> aes256_crypt(const ReqAesEncode &req);

    std::vector<uint8_t> aes256_decrypt(const ReqAesDecode &req);

public:
    explicit rijndael(QObject *parent = nullptr);

    // std::pair<cipher, error code>
    std::pair<QString, QString> aes_crypt(const ReqAesEncode &req);

    // std::pair<raw, error code>
    std::pair<QString, QString> aes_decrypt(const ReqAesDecode &req);
signals:
private:
    crypto::aes aes128;
    crypto::aes192 aes192;
    crypto::aes256 aes256;
};

} // namespace model

#endif // RIJNDAEL_H
