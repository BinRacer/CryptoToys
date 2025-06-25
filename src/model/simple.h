#ifndef SIMPLE_H
#define SIMPLE_H

#include <QJsonDocument>
#include <QJsonObject>
#include <QObject>
#include <crypto/uuencode.h>
#include <crypto/vigenere.h>
#include <crypto/xxencode.h>

namespace model {
namespace crypto = YanLib::crypto;

struct ReqSimpleEncode {
    std::vector<uint8_t> input_text;
    std::vector<uint8_t> key;
    QString which_code;
    static std::pair<bool, ReqSimpleEncode> from_json(const QJsonObject &obj) {
        ReqSimpleEncode simple = {};
        if (!obj.contains("inputText") || !obj.contains("whichCode")) {
            return std::make_pair(false, simple);
        }

        auto temp = obj["inputText"].toString().toStdString();
        simple.input_text.assign(temp.begin(), temp.end());

        simple.which_code = obj["whichCode"].toString();
        if (simple.which_code == "vigenere" && obj.contains("key")) {
            temp = obj["key"].toString().toStdString();
            simple.key.assign(temp.begin(), temp.end());
        }
        return std::make_pair(true, simple);
    }
};

struct ReqSimpleDecode {
    std::vector<uint8_t> input_text;
    std::vector<uint8_t> key;
    QString which_code;
    static std::pair<bool, ReqSimpleDecode> from_json(const QJsonObject &obj) {
        ReqSimpleDecode simple = {};
        if (!obj.contains("inputText") || !obj.contains("whichCode")) {
            return std::make_pair(false, simple);
        }

        auto temp = obj["inputText"].toString().toStdString();
        simple.input_text.assign(temp.begin(), temp.end());

        simple.which_code = obj["whichCode"].toString();
        if (simple.which_code == "vigenere" && obj.contains("key")) {
            temp = obj["key"].toString().toStdString();
            simple.key.assign(temp.begin(), temp.end());
        }
        return std::make_pair(true, simple);
    }
};
class simple : public QObject {
    Q_OBJECT
public:
    explicit simple(QObject *parent = nullptr);

    // std::pair<cipher, error code>
    std::pair<QString, QString> simple_crypt(const ReqSimpleEncode &req);

    // std::pair<raw, error code>
    std::pair<QString, QString> simple_decrypt(const ReqSimpleDecode &req);
signals:
};

} // namespace model

#endif // SIMPLE_H
