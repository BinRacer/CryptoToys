#include "hash.h"

namespace model {

hash::hash(QObject *parent) : QObject{parent} {}

std::pair<QString, QString> hash::hash_crypt(const ReqHashEncode &req) {
    std::vector<uint8_t> encode;
    std::wstring error;
    if (req.which_code == "md5") {
        hash_code::md5 md5(req.input_text);
        encode = md5.hash();
        if (md5.err_code() == 0) {
            error.append(L"Request parameters are invalid");
        } else {
            error.append(L"ErrorCode ");
            error.append(std::to_wstring(md5.err_code()));
            error.append(L": ");
            error.append(md5.err_wstring());
        }
    } else if (req.which_code == "sha1") {
        hash_code::sha1 sha1(req.input_text);
        encode = sha1.hash();
        if (sha1.err_code() == 0) {
            error.append(L"Request parameters are invalid");
        } else {
            error.append(L"ErrorCode ");
            error.append(std::to_wstring(sha1.err_code()));
            error.append(L": ");
            error.append(sha1.err_wstring());
        }
    } else if (req.which_code == "sha256") {
        hash_code::sha256 sha256(req.input_text);
        encode = sha256.hash();
        if (sha256.err_code() == 0) {
            error.append(L"Request parameters are invalid");
        } else {
            error.append(L"ErrorCode ");
            error.append(std::to_wstring(sha256.err_code()));
            error.append(L": ");
            error.append(sha256.err_wstring());
        }
    } else if (req.which_code == "sha384") {
        hash_code::sha384 sha384(req.input_text);
        encode = sha384.hash();
        if (sha384.err_code() == 0) {
            error.append(L"Request parameters are invalid");
        } else {
            error.append(L"ErrorCode ");
            error.append(std::to_wstring(sha384.err_code()));
            error.append(L": ");
            error.append(sha384.err_wstring());
        }
    } else if (req.which_code == "sha512") {
        hash_code::sha512 sha512(req.input_text);
        encode = sha512.hash();
        if (sha512.err_code() == 0) {
            error.append(L"Request parameters are invalid");
        } else {
            error.append(L"ErrorCode ");
            error.append(std::to_wstring(sha512.err_code()));
            error.append(L": ");
            error.append(sha512.err_wstring());
        }
    }
    QByteArray bytes(reinterpret_cast<const char *>(encode.data()),
                     encode.size());
    if (bytes.size() <= 0) {
        auto temp = helper::convert::wstr_to_str(error, helper::CodePage::UTF8);
        return std::make_pair(QString(), QString::fromUtf8(temp));
    }
    return std::make_pair(QString::fromUtf8(bytes.toHex()), QString());
}

} // namespace model
