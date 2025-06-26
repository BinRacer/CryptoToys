#include "service/rest.h"
#include <QApplication>
#include <QIcon>
#include <QLocale>
#include <QMainWindow>
#include <QNetworkProxyFactory>
#include <QWebChannel>
#include <QWebEngineProfile>
#include <QWebEngineSettings>
#include <QWebEngineView>

void web_setting(QMainWindow &window, QWebEngineView &view);

int main(int argc, char *argv[]) {
    // qputenv("QTWEBENGINE_REMOTE_DEBUGGING", "7777");
    QApplication app(argc, argv);
    QLocale::setDefault(QLocale(QLocale::English, QLocale::UnitedStates));
    QNetworkProxyFactory::setUseSystemConfiguration(false);

    QMainWindow main_window;
    main_window.setWindowIcon(QIcon(":/favicon.ico"));
    QWebEngineView web_view(&main_window);

    QWebChannel channel(web_view.page());
    service::rest rest;
    channel.registerObject("restAPI", &rest);
    web_view.page()->setWebChannel(&channel);

    web_setting(main_window, web_view);
    main_window.show();
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
