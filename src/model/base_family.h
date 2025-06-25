#ifndef BASE_FAMILY_H
#define BASE_FAMILY_H

#include <QJsonDocument>
#include <QJsonObject>
#include <QObject>
#include <crypto/base100.h>
#include <crypto/base16.h>
#include <crypto/base32.h>
#include <crypto/base58.h>
#include <crypto/base62.h>
#include <crypto/base64.h>
#include <crypto/base85.h>
#include <crypto/base91.h>
#include <crypto/base92.h>

namespace model {
namespace crypto = YanLib::crypto;

struct ReqBaseEncode {
    std::vector<uint8_t> input_text;
    static std::pair<bool, ReqBaseEncode> from_json(const QJsonObject &obj) {
        ReqBaseEncode base = {};
        if (!obj.contains("inputText")) {
            return std::make_pair(false, base);
        }
        auto temp = obj["inputText"].toString().toStdString();
        base.input_text.assign(temp.begin(), temp.end());
        return std::make_pair(true, base);
    }
};

struct ReqBaseDecode {
    std::vector<uint8_t> input_text;
    static std::pair<bool, ReqBaseDecode> from_json(const QJsonObject &obj) {
        ReqBaseDecode base = {};
        if (!obj.contains("inputText")) {
            return std::make_pair(false, base);
        }
        auto temp = obj["inputText"].toString().toStdString();
        base.input_text.assign(temp.begin(), temp.end());
        return std::make_pair(true, base);
    }
};
class base_family : public QObject {
    Q_OBJECT
public:
    explicit base_family(QObject *parent = nullptr);

    // std::pair<cipher, error code>
    std::pair<QString, QString> base_crypt(const ReqBaseEncode &req,
                                           const int32_t bits);

    // std::pair<raw, error code>
    std::pair<QString, QString> base_decrypt(const ReqBaseDecode &req,
                                             const int32_t bits);
signals:
};

} // namespace model

#endif // BASE_FAMILY_H
