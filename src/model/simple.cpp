#include "simple.h"

namespace model {

simple::simple(QObject *parent) : QObject{parent} {}

std::pair<QString, QString> simple::simple_crypt(const ReqSimpleEncode &req) {
    std::vector<uint8_t> encode;
    if (req.which_code == "uu") {
        encode = crypto::uuencode::encode(req.input_text);
    } else if (req.which_code == "xx") {
        encode = crypto::xxencode::encode(req.input_text);
    } else if (req.which_code == "vigenere") {
        encode = crypto::vigenere::encode(req.input_text, req.key);
    }
    if (encode.empty()) {
        return std::make_pair(QString(), "Request parameters are invalid");
    }
    QByteArray bytes(reinterpret_cast<const char *>(encode.data()),
                     encode.size());
    return std::make_pair(QString::fromUtf8(bytes), QString());
}

std::pair<QString, QString> simple::simple_decrypt(const ReqSimpleDecode &req) {
    std::vector<uint8_t> encode;
    if (req.which_code == "uu") {
        encode = crypto::uuencode::decode(req.input_text);
    } else if (req.which_code == "xx") {
        encode = crypto::xxencode::decode(req.input_text);
    } else if (req.which_code == "vigenere") {
        encode = crypto::vigenere::decode(req.input_text, req.key);
    }
    if (encode.empty()) {
        return std::make_pair(QString(), "Request parameters are invalid");
    }
    QByteArray bytes(reinterpret_cast<const char *>(encode.data()),
                     encode.size());
    return std::make_pair(QString::fromUtf8(bytes), QString());
}
} // namespace model
