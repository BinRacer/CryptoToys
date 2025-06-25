#ifndef PKC_H
#define PKC_H

#include <QJsonDocument>
#include <QJsonObject>
#include <QObject>
#include <crypto/rsa.h>
#include <helper/convert.h>

namespace model {
namespace helper = YanLib::helper;
namespace crypto = YanLib::crypto;

struct ReqRsaGenerate {
    QString key_bits;
    QString output_encoding;
    static std::pair<bool, ReqRsaGenerate> from_json(const QJsonObject &obj) {
        ReqRsaGenerate rsa = {};
        if (!obj.contains("keyBits") || !obj.contains("outputEncoding")) {
            return std::make_pair(false, rsa);
        }
        rsa.key_bits = obj["keyBits"].toString();
        rsa.output_encoding = obj["outputEncoding"].toString();
        return std::make_pair(true, rsa);
    }
};

struct ReqRsaEncode {
    std::vector<uint8_t> input_text;
    std::vector<uint8_t> public_key;
    QString output_encoding;
    static std::pair<bool, ReqRsaEncode> from_json(const QJsonObject &obj) {
        ReqRsaEncode rsa = {};
        if (!obj.contains("inputText") || !obj.contains("publicKey") ||
            !obj.contains("outputEncoding")) {
            return std::make_pair(false, rsa);
        }
        rsa.output_encoding = obj["outputEncoding"].toString();

        auto temp = obj["inputText"].toString().toStdString();
        rsa.input_text.assign(temp.begin(), temp.end());

        auto bytes = obj["publicKey"].toString().toUtf8();
        if (rsa.output_encoding == "Base64") {
            temp = QByteArray::fromBase64(bytes).toStdString();
            rsa.public_key.assign(temp.begin(), temp.end());
        } else if (rsa.output_encoding == "Hex") {
            temp = QByteArray::fromHex(bytes).toStdString();
            rsa.public_key.assign(temp.begin(), temp.end());
        }
        return std::make_pair(true, rsa);
    }
};

struct ReqRsaDecode {
    std::vector<uint8_t> input_text;
    std::vector<uint8_t> private_key;
    QString output_encoding;
    static std::pair<bool, ReqRsaDecode> from_json(const QJsonObject &obj) {
        ReqRsaDecode rsa = {};
        if (!obj.contains("inputText") || !obj.contains("privateKey") ||
            !obj.contains("outputEncoding")) {
            return std::make_pair(false, rsa);
        }

        rsa.output_encoding = obj["outputEncoding"].toString();

        std::string temp;
        auto bytes = obj["inputText"].toString().toUtf8();
        if (rsa.output_encoding == "Base64") {
            temp = QByteArray::fromBase64(bytes).toStdString();
            rsa.input_text.assign(temp.begin(), temp.end());
        } else if (rsa.output_encoding == "Hex") {
            temp = QByteArray::fromHex(bytes).toStdString();
            rsa.input_text.assign(temp.begin(), temp.end());
        }

        bytes = obj["privateKey"].toString().toUtf8();
        if (rsa.output_encoding == "Base64") {
            temp = QByteArray::fromBase64(bytes).toStdString();
            rsa.private_key.assign(temp.begin(), temp.end());
        } else if (rsa.output_encoding == "Hex") {
            temp = QByteArray::fromHex(bytes).toStdString();
            rsa.private_key.assign(temp.begin(), temp.end());
        }
        return std::make_pair(true, rsa);
    }
};

class pkc : public QObject {
    Q_OBJECT
public:
    explicit pkc(QObject *parent = nullptr);

    // std::tuple<public key, private key, error_code>
    std::tuple<QString, QString, QString> rsa_generate(const ReqRsaGenerate &req);

    // std::pair<cipher, error code>
    std::pair<QString, QString> rsa_crypt(const ReqRsaEncode &req);

    // std::pair<raw, error code>
    std::pair<QString, QString> rsa_decrypt(const ReqRsaDecode &req);

signals:
private:
    crypto::rsa rsa;
};

} // namespace model

#endif // PKC_H
