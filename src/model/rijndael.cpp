#include "rijndael.h"

namespace model {

rijndael::rijndael(QObject *parent) : QObject{parent} {}

std::vector<uint8_t> rijndael::aes128_crypt(const ReqAesEncode &req) {
    crypto::AesPadding padding = crypto::AesPadding::PKCS7;
    if (req.padding == "PKCS7") {
        padding = crypto::AesPadding::PKCS7;
    } else if (req.padding == "ISO10126") {
        padding = crypto::AesPadding::ISO10126;
    } else if (req.padding == "ANSIX923") {
        padding = crypto::AesPadding::ANSIX923;
    }
    if (req.mode == "CBC") {
        return aes128.encode_cbc(req.input_text, req.key, req.iv, padding);
    } else if (req.mode == "ECB") {
        return aes128.encode_ecb(req.input_text, req.key, padding);
    } else if (req.mode == "CFB") {
        return aes128.encode_cfb(req.input_text, req.key, req.iv, padding);
    }
    return std::vector<uint8_t>();
}

std::vector<uint8_t> rijndael::aes128_decrypt(const ReqAesDecode &req) {
    crypto::AesPadding padding = crypto::AesPadding::PKCS7;
    if (req.padding == "PKCS7") {
        padding = crypto::AesPadding::PKCS7;
    } else if (req.padding == "ISO10126") {
        padding = crypto::AesPadding::ISO10126;
    } else if (req.padding == "ANSIX923") {
        padding = crypto::AesPadding::ANSIX923;
    }
    if (req.mode == "CBC") {
        return aes128.decode_cbc(req.input_text, req.key, req.iv, padding);
    } else if (req.mode == "ECB") {
        return aes128.decode_ecb(req.input_text, req.key, padding);
    } else if (req.mode == "CFB") {
        return aes128.decode_cfb(req.input_text, req.key, req.iv, padding);
    }
    return std::vector<uint8_t>();
}

std::vector<uint8_t> rijndael::aes192_crypt(const ReqAesEncode &req) {
    crypto::AesPadding padding = crypto::AesPadding::PKCS7;
    if (req.padding == "PKCS7") {
        padding = crypto::AesPadding::PKCS7;
    } else if (req.padding == "ISO10126") {
        padding = crypto::AesPadding::ISO10126;
    } else if (req.padding == "ANSIX923") {
        padding = crypto::AesPadding::ANSIX923;
    }
    if (req.mode == "CBC") {
        return aes192.encode_cbc(req.input_text, req.key, req.iv, padding);
    } else if (req.mode == "ECB") {
        return aes192.encode_ecb(req.input_text, req.key, padding);
    } else if (req.mode == "CFB") {
        return aes192.encode_cfb(req.input_text, req.key, req.iv, padding);
    }
    return std::vector<uint8_t>();
}

std::vector<uint8_t> rijndael::aes192_decrypt(const ReqAesDecode &req) {
    crypto::AesPadding padding = crypto::AesPadding::PKCS7;
    if (req.padding == "PKCS7") {
        padding = crypto::AesPadding::PKCS7;
    } else if (req.padding == "ISO10126") {
        padding = crypto::AesPadding::ISO10126;
    } else if (req.padding == "ANSIX923") {
        padding = crypto::AesPadding::ANSIX923;
    }
    if (req.mode == "CBC") {
        return aes192.decode_cbc(req.input_text, req.key, req.iv, padding);
    } else if (req.mode == "ECB") {
        return aes192.decode_ecb(req.input_text, req.key, padding);
    } else if (req.mode == "CFB") {
        return aes192.decode_cfb(req.input_text, req.key, req.iv, padding);
    }
    return std::vector<uint8_t>();
}

std::vector<uint8_t> rijndael::aes256_crypt(const ReqAesEncode &req) {
    crypto::AesPadding padding = crypto::AesPadding::PKCS7;
    if (req.padding == "PKCS7") {
        padding = crypto::AesPadding::PKCS7;
    } else if (req.padding == "ISO10126") {
        padding = crypto::AesPadding::ISO10126;
    } else if (req.padding == "ANSIX923") {
        padding = crypto::AesPadding::ANSIX923;
    }
    if (req.mode == "CBC") {
        return aes256.encode_cbc(req.input_text, req.key, req.iv, padding);
    } else if (req.mode == "ECB") {
        return aes256.encode_ecb(req.input_text, req.key, padding);
    } else if (req.mode == "CFB") {
        return aes256.encode_cfb(req.input_text, req.key, req.iv, padding);
    }
    return std::vector<uint8_t>();
}

std::vector<uint8_t> rijndael::aes256_decrypt(const ReqAesDecode &req) {
    crypto::AesPadding padding = crypto::AesPadding::PKCS7;
    if (req.padding == "PKCS7") {
        padding = crypto::AesPadding::PKCS7;
    } else if (req.padding == "ISO10126") {
        padding = crypto::AesPadding::ISO10126;
    } else if (req.padding == "ANSIX923") {
        padding = crypto::AesPadding::ANSIX923;
    }
    if (req.mode == "CBC") {
        return aes256.decode_cbc(req.input_text, req.key, req.iv, padding);
    } else if (req.mode == "ECB") {
        return aes256.decode_ecb(req.input_text, req.key, padding);
    } else if (req.mode == "CFB") {
        return aes256.decode_cfb(req.input_text, req.key, req.iv, padding);
    }
    return std::vector<uint8_t>();
}

std::pair<QString, QString> rijndael::aes_crypt(const ReqAesEncode &req) {
    std::vector<uint8_t> encode;
    std::wstring error;
    if (req.key_bits == "128") {
        encode = aes128_crypt(req);
        if (encode.empty()) {
            if (aes128.err_code() == 0) {
                error.append(L"Request parameters are invalid");
            } else {
                error.append(L"ErrorCode ");
                error.append(std::to_wstring(aes128.err_code()));
                error.append(L": ");
                error.append(aes128.err_wstring());
            }
        }
    } else if (req.key_bits == "192") {
        encode = aes192_crypt(req);
        if (encode.empty()) {
            if (aes192.err_code() == 0) {
                error.append(L"Request parameters are invalid");
            } else {
                error.append(L"ErrorCode ");
                error.append(std::to_wstring(aes192.err_code()));
                error.append(L": ");
                error.append(aes192.err_wstring());
            }
        }
    } else if (req.key_bits == "256") {
        encode = aes256_crypt(req);
        if (encode.empty()) {
            if (aes256.err_code() == 0) {
                error.append(L"Request parameters are invalid");
            } else {
                error.append(L"ErrorCode ");
                error.append(std::to_wstring(aes256.err_code()));
                error.append(L": ");
                error.append(aes256.err_wstring());
            }
        }
    }
    QByteArray bytes(reinterpret_cast<const char *>(encode.data()),
                     encode.size());
    if (bytes.size() <= 0) {
        auto temp = helper::convert::wstr_to_str(error, helper::CodePage::UTF8);
        return std::make_pair(QString(), QString::fromUtf8(temp));
    }
    if (req.output_encoding == "Base64") {
        return std::make_pair(QString::fromUtf8(bytes.toBase64()), QString());
    } else if (req.output_encoding == "Hex") {
        return std::make_pair(QString::fromUtf8(bytes.toHex()), QString());
    }
    return std::make_pair(QString(), QString());
}

std::pair<QString, QString> rijndael::aes_decrypt(const ReqAesDecode &req) {
    std::vector<uint8_t> decode;
    std::wstring error;
    if (req.key_bits == "128") {
        decode = aes128_decrypt(req);
        if (decode.empty()) {
            if (aes128.err_code() == 0) {
                error.append(L"Request parameters are invalid");
            } else {
                error.append(L"ErrorCode ");
                error.append(std::to_wstring(aes128.err_code()));
                error.append(L": ");
                error.append(aes128.err_wstring());
            }
        }
    } else if (req.key_bits == "192") {
        decode = aes192_decrypt(req);
        if (decode.empty()) {
            if (aes192.err_code() == 0) {
                error.append(L"Request parameters are invalid");
            } else {
                error.append(L"ErrorCode ");
                error.append(std::to_wstring(aes192.err_code()));
                error.append(L": ");
                error.append(aes192.err_wstring());
            }
        }
    } else if (req.key_bits == "256") {
        decode = aes256_decrypt(req);
        if (decode.empty()) {
            if (aes256.err_code() == 0) {
                error.append(L"Request parameters are invalid");
            } else {
                error.append(L"ErrorCode ");
                error.append(std::to_wstring(aes256.err_code()));
                error.append(L": ");
                error.append(aes256.err_wstring());
            }
        }
    }
    QByteArray bytes(reinterpret_cast<const char *>(decode.data()),
                     decode.size());
    if (bytes.size() <= 0) {
        auto temp = helper::convert::wstr_to_str(error, helper::CodePage::UTF8);
        return std::make_pair(QString::fromUtf8(bytes), QString::fromUtf8(temp));
    }
    return std::make_pair(QString::fromUtf8(bytes), QString());
}

} // namespace model
