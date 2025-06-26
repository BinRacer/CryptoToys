#ifndef REST_H
#define REST_H

#include <QHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QObject>
#include <model/base_family.h>
#include <model/hash.h>
#include <model/pkc.h>
#include <model/rijndael.h>
#include <model/simple.h>

namespace service {
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

class rest : public QObject {
    Q_OBJECT
private:
    void ok_resp(QString data);

    void err_resp(QString message);

    void post(const QString &path, const QJsonObject &data);

public:
    explicit rest(QObject *parent = nullptr);

    void aes_encode(const QJsonObject &data);

    void aes_decode(const QJsonObject &data);

    void rsa_generate(const QJsonObject &data);

    void rsa_encode(const QJsonObject &data);

    void rsa_decode(const QJsonObject &data);

    void base_encode(const QJsonObject &data);

    void base_decode(const QJsonObject &data);

    void simple_encode(const QJsonObject &data);

    void simple_decode(const QJsonObject &data);

    void hash_encode(const QJsonObject &data);

public slots:
    void request(const QString &method, const QString &path,
                 const QJsonObject &data);

signals:
    void response(int32_t status, const QJsonObject &result);

private:
    using handler = std::function<void(const QJsonObject &data)>;
    QHash<QString, handler> routes;
    model::rijndael aes;
    model::pkc rsa;
    model::base_family base_family;
    model::simple simple;
    model::hash hash;
};

} // namespace service

#endif // REST_H
