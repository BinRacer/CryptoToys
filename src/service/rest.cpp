#include "rest.h"

namespace service {

rest::rest(QObject *parent) : QObject{parent} {
    routes.insert("/api/aes/encode",
                  [this](const QJsonObject &data) { this->aes_encode(data); });
    routes.insert("/api/aes/decode",
                  [this](const QJsonObject &data) { this->aes_decode(data); });

    routes.insert("/api/rsa/generate",
                  [this](const QJsonObject &data) { this->rsa_generate(data); });
    routes.insert("/api/rsa/encode",
                  [this](const QJsonObject &data) { this->rsa_encode(data); });
    routes.insert("/api/rsa/decode",
                  [this](const QJsonObject &data) { this->rsa_decode(data); });

    routes.insert("/api/base/encode",
                  [this](const QJsonObject &data) { this->base_encode(data); });
    routes.insert("/api/base/decode",
                  [this](const QJsonObject &data) { this->base_decode(data); });

    routes.insert("/api/simple/encode",
                  [this](const QJsonObject &data) { this->simple_encode(data); });

    routes.insert("/api/simple/decode",
                  [this](const QJsonObject &data) { this->simple_decode(data); });

    routes.insert("/api/hash/encode",
                  [this](const QJsonObject &data) { this->hash_encode(data); });
}

void rest::ok_resp(QString data) {
    Resp resp;
    resp.code = 200, resp.data = data;
    emit response(200, resp.to_json());
    return;
}

void rest::err_resp(QString message) {
    Resp resp;
    resp.code = 400, resp.message = message;
    emit response(200, resp.to_json());
    return;
}

void rest::aes_encode(const QJsonObject &data) {
    const auto &[is_ok, json_data] = model::ReqAesEncode::from_json(data);
    if (!is_ok) {
        err_resp("Request parameters are invalid");
        return;
    }
    const auto &[cipher, error] = aes.aes_crypt(json_data);
    if (cipher.size() <= 0) {
        err_resp(error);
        return;
    }
    ok_resp(cipher);
    return;
}

void rest::aes_decode(const QJsonObject &data) {
    const auto &[is_ok, json_data] = model::ReqAesDecode::from_json(data);
    if (!is_ok) {
        err_resp("Request parameters are invalid");
        return;
    }
    const auto &[cipher, error] = aes.aes_decrypt(json_data);
    if (cipher.size() <= 0) {
        err_resp(error);
        return;
    }
    ok_resp(cipher);
    return;
}

void rest::rsa_generate(const QJsonObject &data) {
    const auto &[is_ok, json_data] = model::ReqRsaGenerate::from_json(data);
    if (!is_ok) {
        err_resp("Request parameters are invalid");
        return;
    }
    const auto &[pub, priv, error] = rsa.rsa_generate(json_data);
    if (error.size() > 0) {
        err_resp(error);
        return;
    }
    QString result("{\"publicKey\":\"");
    result.append(pub);
    result.append("\",\"privateKey\":\"");
    result.append(priv);
    result.append("\"}");
    ok_resp(result);
    return;
}

void rest::rsa_encode(const QJsonObject &data) {
    const auto &[is_ok, json_data] = model::ReqRsaEncode::from_json(data);
    if (!is_ok) {
        err_resp("Request parameters are invalid");
        return;
    }
    const auto &[cipher, error] = rsa.rsa_crypt(json_data);
    if (cipher.size() <= 0) {
        err_resp(error);
        return;
    }
    ok_resp(cipher);
    return;
}

void rest::rsa_decode(const QJsonObject &data) {
    const auto &[is_ok, json_data] = model::ReqRsaDecode::from_json(data);
    if (!is_ok) {
        err_resp("Request parameters are invalid");
        return;
    }
    const auto &[raw, error] = rsa.rsa_decrypt(json_data);
    if (raw.size() <= 0) {
        err_resp(error);
        return;
    }
    ok_resp(raw);
    return;
}

void rest::base_encode(const QJsonObject &data) {
    const auto &[is_ok, json_data] = model::ReqBaseEncode::from_json(data);
    if (!is_ok) {
        err_resp("Request parameters are invalid");
        return;
    }
    const auto &[cipher, error] = base_family.base_crypt(json_data);
    if (cipher.size() <= 0) {
        err_resp(error);
        return;
    }
    ok_resp(cipher);
    return;
}

void rest::base_decode(const QJsonObject &data) {
    const auto &[is_ok, json_data] = model::ReqBaseDecode::from_json(data);
    if (!is_ok) {
        err_resp("Request parameters are invalid");
        return;
    }
    const auto &[raw, error] = base_family.base_decrypt(json_data);
    if (raw.size() <= 0) {
        err_resp(error);
        return;
    }
    ok_resp(raw);
    return;
}

void rest::simple_encode(const QJsonObject &data) {
    const auto &[is_ok, json_data] = model::ReqSimpleEncode::from_json(data);
    if (!is_ok) {
        err_resp("Request parameters are invalid");
        return;
    }
    const auto &[cipher, error] = simple.simple_crypt(json_data);
    if (cipher.size() <= 0) {
        err_resp(error);
        return;
    }
    ok_resp(cipher);
    return;
}

void rest::simple_decode(const QJsonObject &data) {
    const auto &[is_ok, json_data] = model::ReqSimpleDecode::from_json(data);
    if (!is_ok) {
        err_resp("Request parameters are invalid");
        return;
    }
    const auto &[raw, error] = simple.simple_decrypt(json_data);
    if (raw.size() <= 0) {
        err_resp(error);
        return;
    }
    ok_resp(raw);
    return;
}

void rest::hash_encode(const QJsonObject &data) {
    const auto &[is_ok, json_data] = model::ReqHashEncode::from_json(data);
    if (!is_ok) {
        err_resp("Request parameters are invalid");
        return;
    }
    const auto &[cipher, error] = hash.hash_crypt(json_data);
    if (cipher.size() <= 0) {
        err_resp(error);
        return;
    }
    ok_resp(cipher);
    return;
}

void rest::post(const QString &path, const QJsonObject &data) {
    if (routes.contains(path)) {
        handler func = routes.value(path);
        func(data);
    } else {
        err_resp("Request Path are invalid");
    }
    return;
}

void rest::request(const QString &method, const QString &path,
                   const QJsonObject &data) {
    if (method == "POST") {
        post(path, data);
        return;
    }
}

} // namespace service
