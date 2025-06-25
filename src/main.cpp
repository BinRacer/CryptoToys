#include "route/route.h"
#include <QApplication>
#include <QHttpServer>
#include <QLocale>
#include <QMainWindow>
#include <QNetworkReply>
#include <QTcpServer>
#include <QWebEngineProfile>
#include <QWebEngineSettings>
#include <QWebEngineView>
#include <QIcon>

void web_setting(QMainWindow &window, QWebEngineView &view);

int main(int argc, char *argv[]) {
    // qputenv("QTWEBENGINE_REMOTE_DEBUGGING", "7777");
    QApplication app(argc, argv);
    QLocale::setDefault(QLocale(QLocale::English, QLocale::UnitedStates));
    QNetworkProxyFactory::setUseSystemConfiguration(false);

    QMainWindow main_window;
    main_window.setWindowIcon(QIcon(":/favicon.ico"));
    QWebEngineView web_view(&main_window);
    web_setting(main_window, web_view);
    main_window.show();

    route::route route;
    route.init();
    auto tcpserver = std::make_unique<QTcpServer>();
    if (!tcpserver->listen(QHostAddress::LocalHost, 8888) ||
        !route.bind(tcpserver.get())) {
        qDebug() << QCoreApplication::translate(
            "CryptoToys", "Server failed to start http://127.0.0.1:8888/");
        return 0;
    }
    tcpserver.release();
    qDebug() << QCoreApplication::translate("CryptoToys",
                                            "Running on http://127.0.0.1:8888/");
    return app.exec();
}

void web_setting(QMainWindow &window, QWebEngineView &view) {
    view.settings()->setAttribute(QWebEngineSettings::Accelerated2dCanvasEnabled,
                                  true);
    view.settings()->setAttribute(QWebEngineSettings::WebGLEnabled, true);
    view.settings()->setAttribute(QWebEngineSettings::AutoLoadImages, true);
    view.settings()->setAttribute(QWebEngineSettings::JavascriptEnabled, true);
    view.settings()->setAttribute(
        QWebEngineSettings::JavascriptCanAccessClipboard, true);
    view.settings()->setAttribute(QWebEngineSettings::PluginsEnabled, true);
    view.settings()->setAttribute(QWebEngineSettings::LocalStorageEnabled, true);
    view.settings()->setAttribute(QWebEngineSettings::FullScreenSupportEnabled,
                                  true);

    view.page()->profile()->setHttpCacheType(QWebEngineProfile::MemoryHttpCache);
    view.page()->profile()->setHttpCacheMaximumSize(50 * 1024 * 1024);

    window.setCentralWidget(&view);
    window.setWindowState(Qt::WindowMaximized);
    view.load(QUrl("qrc:/index.html"));
}
