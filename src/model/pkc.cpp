#include "pkc.h"

namespace model {

pkc::pkc(QObject *parent) : QObject{parent} {}

std::tuple<QString, QString, QString>
pkc::rsa_generate(const ReqRsaGenerate &req) {
    crypto::RsaKeyBits bits = crypto::RsaKeyBits::Bit4096;
    if (req.key_bits == "512") {
        bits = crypto::RsaKeyBits::Bit512;
    } else if (req.key_bits == "1024") {
        bits = crypto::RsaKeyBits::Bit1024;
    } else if (req.key_bits == "2048") {
        bits = crypto::RsaKeyBits::Bit2048;
    } else if (req.key_bits == "4096") {
        bits = crypto::RsaKeyBits::Bit4096;
    }
    QString pub;
    QString priv;
    std::wstring error;
    if (!rsa.generate_key(bits)) {
        if (rsa.err_code() == 0) {
            error.append(L"Request parameters are invalid");
        } else {
            error.append(L"ErrorCode ");
            error.append(std::to_wstring(rsa.err_code()));
            error.append(L": ");
            error.append(rsa.err_wstring());
        }
        auto temp = helper::convert::wstr_to_str(error, helper::CodePage::UTF8);
        return std::make_tuple(pub, priv, QString::fromUtf8(temp));
    }
    if (req.output_encoding == "Base64") {
        pub = QString::fromStdString(rsa.pub_base64());
        priv = QString::fromStdString(rsa.priv_base64());
    } else if (req.output_encoding == "Hex") {
        pub = QString::fromStdString(rsa.pub_hex());
        priv = QString::fromStdString(rsa.priv_hex());
    }
    return std::make_tuple(pub, priv, QString());
}

std::pair<QString, QString> pkc::rsa_crypt(const ReqRsaEncode &req) {
    auto encode = rsa.encode(req.input_text, req.public_key);
    std::wstring error;
    if (encode.empty()) {
        if (rsa.err_code() == 0) {
            error.append(L"Request parameters are invalid");
        } else {
            error.append(L"ErrorCode ");
            error.append(std::to_wstring(rsa.err_code()));
            error.append(L": ");
            error.append(rsa.err_wstring());
        }
        auto temp = helper::convert::wstr_to_str(error, helper::CodePage::UTF8);
        return std::make_pair(QString(), QString::fromUtf8(temp));
    }
    QByteArray bytes(reinterpret_cast<const char *>(encode.data()),
                     encode.size());
    if (req.output_encoding == "Base64") {
        return std::make_pair(QString::fromUtf8(bytes.toBase64()), QString());
    } else if (req.output_encoding == "Hex") {
        return std::make_pair(QString::fromUtf8(bytes.toHex()), QString());
    }
    return std::make_pair(QString(), QString());
}

std::pair<QString, QString> pkc::rsa_decrypt(const ReqRsaDecode &req) {
    auto decode = rsa.decode(req.input_text, req.private_key);
    std::wstring error;
    if (decode.empty()) {
        if (rsa.err_code() == 0) {
            error.append(L"Request parameters are invalid");
        } else {
            error.append(L"ErrorCode ");
            error.append(std::to_wstring(rsa.err_code()));
            error.append(L": ");
            error.append(rsa.err_wstring());
        }
        auto temp = helper::convert::wstr_to_str(error, helper::CodePage::UTF8);
        return std::make_pair(QString(), QString::fromUtf8(temp));
    }
    QByteArray bytes(reinterpret_cast<const char *>(decode.data()),
                     decode.size());
    return std::make_pair(QString::fromUtf8(bytes), QString());
}

} // namespace model
