#ifndef HASH_H
#define HASH_H

#include <QJsonDocument>
#include <QJsonObject>
#include <QObject>
#include <hash/md5.h>
#include <hash/sha1.h>
#include <hash/sha256.h>
#include <hash/sha384.h>
#include <hash/sha512.h>
#include <helper/helper.h>

namespace model {
namespace helper = YanLib::helper;
namespace hash_code = YanLib::hash;

struct ReqHashEncode {
    std::vector<uint8_t> input_text;
    QString which_code;
    static std::pair<bool, ReqHashEncode> from_json(const QJsonObject &obj) {
        ReqHashEncode code = {};
        if (!obj.contains("inputText") || !obj.contains("whichCode")) {
            return std::make_pair(false, code);
        }

        auto temp = obj["inputText"].toString().toStdString();
        code.input_text.assign(temp.begin(), temp.end());

        code.which_code = obj["whichCode"].toString();
        return std::make_pair(true, code);
    }
};

class hash : public QObject {
    Q_OBJECT
public:
    explicit hash(QObject *parent = nullptr);

    // std::pair<cipher, error code>
    std::pair<QString, QString> hash_crypt(const ReqHashEncode &req);
signals:
};

} // namespace model

#endif // HASH_H
