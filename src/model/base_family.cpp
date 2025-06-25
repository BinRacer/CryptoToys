#include "base_family.h"

namespace model {

base_family::base_family(QObject *parent) : QObject{parent} {}

std::pair<QString, QString> base_family::base_crypt(const ReqBaseEncode &req,
                                                    const int32_t bits) {
    std::vector<uint8_t> encode;
    switch (bits) {
    case 16:
        encode = crypto::base16::encode(req.input_text);
        break;
    case 32:
        encode = crypto::base32::encode(req.input_text);
        break;
    case 58:
        encode = crypto::base58::encode(req.input_text);
        break;
    case 62:
        encode = crypto::base62::encode(req.input_text);
        break;
    case 64:
        encode = crypto::base64::encode(req.input_text);
        break;
    case 6464:
        encode = crypto::base64::encode_url(req.input_text);
        break;
    case 85:
        encode = crypto::base85::encode(req.input_text);
        break;
    case 91:
        encode = crypto::base91::encode(req.input_text);
        break;
    case 92:
        encode = crypto::base92::encode(req.input_text);
        break;
    case 100:
        encode = crypto::base100::encode(req.input_text);
        break;
    default:
        break;
    }
    if (encode.empty()) {
        return std::make_pair(QString(), "Request parameters are invalid");
    }
    QByteArray bytes(reinterpret_cast<const char *>(encode.data()),
                     encode.size());
    return std::make_pair(QString::fromUtf8(bytes), QString());
}

std::pair<QString, QString> base_family::base_decrypt(const ReqBaseDecode &req,
                                                      const int32_t bits) {
    std::vector<uint8_t> decode;
    switch (bits) {
    case 16:
        decode = crypto::base16::decode(req.input_text);
        break;
    case 32:
        decode = crypto::base32::decode(req.input_text);
        break;
    case 58:
        decode = crypto::base58::decode(req.input_text);
        break;
    case 62:
        decode = crypto::base62::decode(req.input_text);
        break;
    case 64:
        decode = crypto::base64::decode(req.input_text);
        break;
    case 6464:
        decode = crypto::base64::decode_url(req.input_text);
        break;
    case 85:
        decode = crypto::base85::decode(req.input_text);
        break;
    case 91:
        decode = crypto::base91::decode(req.input_text);
        break;
    case 92:
        decode = crypto::base92::decode(req.input_text);
        break;
    case 100:
        decode = crypto::base100::decode(req.input_text);
        break;
    default:
        break;
    }
    if (decode.empty()) {
        return std::make_pair(QString(), "Request parameters are invalid");
    }
    QByteArray bytes(reinterpret_cast<const char *>(decode.data()),
                     decode.size());
    return std::make_pair(QString::fromUtf8(bytes), QString());
}

} // namespace model
