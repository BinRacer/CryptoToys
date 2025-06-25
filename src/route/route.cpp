#include "route.h"

namespace route {
route::route(QObject *parent) : QObject{parent} {}

void route::make_cors(QHttpHeaders &headers) {
    // headers.append("Access-Control-Allow-Origin", "qrc:");
    headers.append("Access-Control-Allow-Origin", "*");
    headers.append("Access-Control-Allow-Methods", "POST, OPTIONS");
    headers.append("Access-Control-Allow-Headers", "*");
    headers.append("Access-Control-Expose-Headers",
                   "Content-Length, Access-Control-Allow-Origin, "
                   "Access-Control-Allow-Headers, Cache-Control, "
                   "Content-Language, Content-Type");
    headers.append("Access-Control-Allow-Credentials", "true");
}

void route::enable_cors(const QHttpServerRequest &request,
                        QHttpServerResponder &responder) {
    QHttpHeaders headers;
    make_cors(headers);
    responder.write(headers, QHttpServerResponder::StatusCode::NoContent);
}

void route::ok_resp(QJsonObject &&obj, QHttpServerResponder &responder) {
    QHttpHeaders headers;
    make_cors(headers);
    headers.append("Content-Type", "application/json; charset=utf-8");
    headers.append("Cache-Control", "no-cache");
    responder.write(QJsonDocument(obj), headers,
                    QHttpServerResponder::StatusCode::Ok);
}

void route::err_resp(QString message, QHttpServerResponder &responder) {
    Resp resp;
    resp.code = 400, resp.message = message;
    QHttpHeaders headers;
    make_cors(headers);
    headers.append("Content-Type", "application/json; charset=utf-8");
    headers.append("Cache-Control", "no-cache");
    responder.write(QJsonDocument(resp.to_json()), headers,
                    QHttpServerResponder::StatusCode::Ok);
}

void route::aes_encode(const QHttpServerRequest &request,
                       QHttpServerResponder &responder) {
    QJsonParseError err;
    const auto json = QJsonDocument::fromJson(request.body(), &err);
    if (err.error || !json.isObject()) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[is_ok, json_data] =
        model::ReqAesEncode::from_json(json.object());
    if (!is_ok) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[cipher, error] = aes.aes_crypt(json_data);
    if (cipher.size() <= 0) {
        err_resp(error, responder);
        return;
    }
    Resp resp;
    resp.code = 200;
    resp.data = cipher;
    ok_resp(resp.to_json(), responder);
    return;
}

void route::aes_decode(const QHttpServerRequest &request,
                       QHttpServerResponder &responder) {
    QJsonParseError err;
    const auto json = QJsonDocument::fromJson(request.body(), &err);
    if (err.error || !json.isObject()) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[is_ok, json_data] =
        model::ReqAesDecode::from_json(json.object());
    if (!is_ok) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[raw, error] = aes.aes_decrypt(json_data);
    if (raw.size() <= 0) {
        err_resp(error, responder);
        return;
    }
    Resp resp;
    resp.code = 200;
    resp.data = raw;
    ok_resp(resp.to_json(), responder);
    return;
}

void route::rsa_generate(const QHttpServerRequest &request,
                         QHttpServerResponder &responder) {
    QJsonParseError err;
    const auto json = QJsonDocument::fromJson(request.body(), &err);
    if (err.error || !json.isObject()) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[is_ok, json_data] =
        model::ReqRsaGenerate::from_json(json.object());
    if (!is_ok) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[pub, priv, error] = rsa.rsa_generate(json_data);
    if (error.size() > 0) {
        err_resp(error, responder);
        return;
    }
    QString result("{\"publicKey\":\"");
    result.append(pub);
    result.append("\",\"privateKey\":\"");
    result.append(priv);
    result.append("\"}");
    Resp resp;
    resp.code = 200;
    resp.data = result;
    ok_resp(resp.to_json(), responder);
    return;
}

void route::rsa_encode(const QHttpServerRequest &request,
                       QHttpServerResponder &responder) {
    QJsonParseError err;
    const auto json = QJsonDocument::fromJson(request.body(), &err);
    if (err.error || !json.isObject()) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[is_ok, json_data] =
        model::ReqRsaEncode::from_json(json.object());
    if (!is_ok) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[cipher, error] = rsa.rsa_crypt(json_data);
    if (cipher.size() <= 0) {
        err_resp(error, responder);
        return;
    }
    Resp resp;
    resp.code = 200;
    resp.data = cipher;
    ok_resp(resp.to_json(), responder);
    return;
}

void route::rsa_decode(const QHttpServerRequest &request,
                       QHttpServerResponder &responder) {
    QJsonParseError err;
    const auto json = QJsonDocument::fromJson(request.body(), &err);
    if (err.error || !json.isObject()) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[is_ok, json_data] =
        model::ReqRsaDecode::from_json(json.object());
    if (!is_ok) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[raw, error] = rsa.rsa_decrypt(json_data);
    if (raw.size() <= 0) {
        err_resp(error, responder);
        return;
    }
    Resp resp;
    resp.code = 200;
    resp.data = raw;
    ok_resp(resp.to_json(), responder);
    return;
}

void route::base_encode(const QHttpServerRequest &request,
                        QHttpServerResponder &responder, const int32_t bits) {
    QJsonParseError err;
    const auto json = QJsonDocument::fromJson(request.body(), &err);
    if (err.error || !json.isObject()) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[is_ok, json_data] =
        model::ReqBaseEncode::from_json(json.object());
    if (!is_ok) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[cipher, error] = base_family.base_crypt(json_data, bits);
    if (cipher.size() <= 0) {
        err_resp(error, responder);
        return;
    }
    Resp resp;
    resp.code = 200;
    resp.data = cipher;
    ok_resp(resp.to_json(), responder);
    return;
}

void route::base_decode(const QHttpServerRequest &request,
                        QHttpServerResponder &responder, const int32_t bits) {
    QJsonParseError err;
    const auto json = QJsonDocument::fromJson(request.body(), &err);
    if (err.error || !json.isObject()) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[is_ok, json_data] =
        model::ReqBaseDecode::from_json(json.object());
    if (!is_ok) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[raw, error] = base_family.base_decrypt(json_data, bits);
    if (raw.size() <= 0) {
        err_resp(error, responder);
        return;
    }
    Resp resp;
    resp.code = 200;
    resp.data = raw;
    ok_resp(resp.to_json(), responder);
    return;
}

void route::simple_encode(const QHttpServerRequest &request,
                          QHttpServerResponder &responder) {
    QJsonParseError err;
    const auto json = QJsonDocument::fromJson(request.body(), &err);
    if (err.error || !json.isObject()) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[is_ok, json_data] =
        model::ReqSimpleEncode::from_json(json.object());
    if (!is_ok) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[cipher, error] = simple.simple_crypt(json_data);
    if (cipher.size() <= 0) {
        err_resp(error, responder);
        return;
    }
    Resp resp;
    resp.code = 200;
    resp.data = cipher;
    ok_resp(resp.to_json(), responder);
    return;
}

void route::simple_decode(const QHttpServerRequest &request,
                          QHttpServerResponder &responder) {
    QJsonParseError err;
    const auto json = QJsonDocument::fromJson(request.body(), &err);
    if (err.error || !json.isObject()) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[is_ok, json_data] =
        model::ReqSimpleDecode::from_json(json.object());
    if (!is_ok) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[raw, error] = simple.simple_decrypt(json_data);
    if (raw.size() <= 0) {
        err_resp(error, responder);
        return;
    }
    Resp resp;
    resp.code = 200;
    resp.data = raw;
    ok_resp(resp.to_json(), responder);
    return;
}

void route::hash_encode(const QHttpServerRequest &request,
                        QHttpServerResponder &responder) {
    QJsonParseError err;
    const auto json = QJsonDocument::fromJson(request.body(), &err);
    if (err.error || !json.isObject()) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[is_ok, json_data] =
        model::ReqHashEncode::from_json(json.object());
    if (!is_ok) {
        err_resp("Request parameters are invalid", responder);
        return;
    }
    const auto &[cipher, error] = hash.hash_crypt(json_data);
    if (cipher.size() <= 0) {
        err_resp(error, responder);
        return;
    }
    Resp resp;
    resp.code = 200;
    resp.data = cipher;
    ok_resp(resp.to_json(), responder);
    return;
}

void route::init() {
    QVector<QString> cors = {
        "/api/aes/encode",       "/api/aes/decode",       "/api/rsa/generate",
        "/api/rsa/encode",       "/api/rsa/decode",       "/api/base16/encode",
        "/api/base16/decode",    "/api/base32/encode",    "/api/base32/decode",
        "/api/base58/encode",    "/api/base58/decode",    "/api/base62/encode",
        "/api/base62/decode",    "/api/base64/encode",    "/api/base64/decode",
        "/api/base64url/encode", "/api/base64url/decode", "/api/base85/encode",
        "/api/base85/decode",    "/api/base91/encode",    "/api/base91/decode",
        "/api/base92/encode",    "/api/base92/decode",    "/api/base100/encode",
        "/api/base100/decode",   "/api/simple/encode",    "/api/simple/decode",
        "/api/hash/encode",
    };
    for (auto &path : cors) {
        server.route(path, QHttpServerRequest::Method::Options,
                     [&](const QHttpServerRequest &request,
                         QHttpServerResponder &responder) {
            enable_cors(request, responder);
        });
    }

    server.route(
        "/api/aes/encode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            aes_encode(request, responder);
        });
    server.route(
        "/api/aes/decode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            aes_decode(request, responder);
        });

    server.route(
        "/api/rsa/generate", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            rsa_generate(request, responder);
        });
    server.route(
        "/api/rsa/encode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            rsa_encode(request, responder);
        });
    server.route(
        "/api/rsa/decode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            rsa_decode(request, responder);
        });

    server.route(
        "/api/base16/encode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_encode(request, responder, 16);
        });
    server.route(
        "/api/base16/decode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_decode(request, responder, 16);
        });

    server.route(
        "/api/base32/encode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_encode(request, responder, 32);
        });
    server.route(
        "/api/base32/decode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_decode(request, responder, 32);
        });

    server.route(
        "/api/base58/encode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_encode(request, responder, 58);
        });
    server.route(
        "/api/base58/decode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_decode(request, responder, 58);
        });

    server.route(
        "/api/base62/encode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_encode(request, responder, 62);
        });
    server.route(
        "/api/base62/decode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_decode(request, responder, 62);
        });

    server.route(
        "/api/base64/encode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_encode(request, responder, 64);
        });
    server.route(
        "/api/base64/decode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_decode(request, responder, 64);
        });

    server.route(
        "/api/base64url/encode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_encode(request, responder, 6464);
        });
    server.route(
        "/api/base64url/decode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_decode(request, responder, 6464);
        });

    server.route(
        "/api/base85/encode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_encode(request, responder, 85);
        });
    server.route(
        "/api/base85/decode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_decode(request, responder, 85);
        });

    server.route(
        "/api/base91/encode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_encode(request, responder, 91);
        });
    server.route(
        "/api/base91/decode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_decode(request, responder, 91);
        });

    server.route(
        "/api/base92/encode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_encode(request, responder, 92);
        });
    server.route(
        "/api/base92/decode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_decode(request, responder, 92);
        });

    server.route(
        "/api/base100/encode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_encode(request, responder, 100);
        });
    server.route(
        "/api/base100/decode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            base_decode(request, responder, 100);
        });

    server.route(
        "/api/simple/encode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            simple_encode(request, responder);
        });
    server.route(
        "/api/simple/decode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            simple_decode(request, responder);
        });

    server.route(
        "/api/hash/encode", QHttpServerRequest::Method::Post,
        [&](const QHttpServerRequest &request, QHttpServerResponder &responder) {
            hash_encode(request, responder);
        });
}

bool route::bind(QTcpServer *tcp_server) { return server.bind(tcp_server); }
} // namespace route
