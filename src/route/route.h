#ifndef ROUTE_H
#define ROUTE_H

#include <QHttpServer>
#include <QHttpServerRequest>
#include <QHttpServerResponder>
#include <QJsonDocument>
#include <QJsonObject>
#include <QObject>
#include <QTcpServer>
#include <QVector>
#include <model/base_family.h>
#include <model/hash.h>
#include <model/pkc.h>
#include <model/rijndael.h>
#include <model/simple.h>

namespace route {
struct Resp {
    int32_t code;
    QString message;
    QString data;

    QJsonObject to_json() const {
        QJsonObject obj;
        obj["code"] = code;
        obj["message"] = message;
        obj["data"] = data;
        return obj;
    }
};

class route : public QObject {
    Q_OBJECT

private:
    void make_cors(QHttpHeaders &headers);

    void enable_cors(const QHttpServerRequest &request,
                     QHttpServerResponder &responder);

    void ok_resp(QJsonObject &&obj, QHttpServerResponder &responder);

    void err_resp(QString message, QHttpServerResponder &responder);

    void aes_encode(const QHttpServerRequest &request,
                    QHttpServerResponder &responder);

    void aes_decode(const QHttpServerRequest &request,
                    QHttpServerResponder &responder);

    void rsa_generate(const QHttpServerRequest &request,
                    QHttpServerResponder &responder);

    void rsa_encode(const QHttpServerRequest &request,
                    QHttpServerResponder &responder);

    void rsa_decode(const QHttpServerRequest &request,
                    QHttpServerResponder &responder);

    void base_encode(const QHttpServerRequest &request,
                     QHttpServerResponder &responder, const int32_t bits);

    void base_decode(const QHttpServerRequest &request,
                     QHttpServerResponder &responder, const int32_t bits);

    void simple_encode(const QHttpServerRequest &request,
                       QHttpServerResponder &responder);

    void simple_decode(const QHttpServerRequest &request,
                       QHttpServerResponder &responder);

    void hash_encode(const QHttpServerRequest &request,
                     QHttpServerResponder &responder);

public:
    explicit route(QObject *parent = nullptr);

    void init();

    bool bind(QTcpServer *tcp_server);
signals:
private:
    QHttpServer server;
    model::rijndael aes;
    model::pkc rsa;
    model::base_family base_family;
    model::simple simple;
    model::hash hash;
};
} // namespace route

#endif // ROUTE_H
