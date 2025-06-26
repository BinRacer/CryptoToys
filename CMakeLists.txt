cmake_minimum_required(VERSION 3.16)

project(CryptoToys VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS
    Core
    Gui
    Widgets
    WebEngineWidgets
    WebChannel
    Network
)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS
    Core
    Gui
    Widgets
    WebEngineWidgets
    WebChannel
    Network
)

include_directories(${CMAKE_SOURCE_DIR}/src)

include_directories(${CMAKE_SOURCE_DIR}/YanLib/include)

set(PROJECT_SOURCES
    src/main.cpp
    src/service/rest.h
    src/service/rest.cpp
    src/model/rijndael.h
    src/model/rijndael.cpp
    src/model/pkc.h
    src/model/pkc.cpp
    src/model/base_family.h
    src/model/base_family.cpp
    src/model/simple.h
    src/model/simple.cpp
    src/model/hash.h
    src/model/hash.cpp
    ui.qrc
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    find_package(Qt6 REQUIRED COMPONENTS Core)

    qt_add_executable(CryptoToys
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )
# Define target properties for Android with Qt 6 as:
#    set_property(TARGET CryptoToys APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
#                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation
else()
    if(ANDROID)
        add_library(CryptoToys SHARED
            ${PROJECT_SOURCES}
        )
# Define properties for Android with Qt 5 after find_package() calls as:
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
    else()
        add_executable(CryptoToys
            ${PROJECT_SOURCES}
        )
    endif()
endif()

target_link_libraries(CryptoToys PRIVATE
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::Gui
    Qt${QT_VERSION_MAJOR}::Widgets
    Qt${QT_VERSION_MAJOR}::WebEngineWidgets
    Qt${QT_VERSION_MAJOR}::WebChannel
    Qt${QT_VERSION_MAJOR}::Network
    $<$<CONFIG:Debug>:${CMAKE_SOURCE_DIR}/YanLib/lib/x64/Debug/YanLibd.lib>
    $<$<CONFIG:Release>:${CMAKE_SOURCE_DIR}/YanLib/lib/x64/Release/YanLib.lib>
)
target_link_libraries(CryptoToys PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::WebEngineWidgets
    Qt6::WebChannel
    Qt6::Network
    $<$<CONFIG:Debug>:${CMAKE_SOURCE_DIR}/YanLib/lib/x64/Debug/YanLibd.lib>
    $<$<CONFIG:Release>:${CMAKE_SOURCE_DIR}/YanLib/lib/x64/Release/YanLib.lib>
)
target_link_libraries(CryptoToys PRIVATE Qt6::Core)

set(APP_ICON_RESOURCE ${CMAKE_CURRENT_SOURCE_DIR}/app.rc)
target_sources(CryptoToys PRIVATE ${APP_ICON_RESOURCE})

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# If you are developing for iOS or macOS you should consider setting an
# explicit, fixed bundle identifier manually though.
if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.CryptoToys)
endif()
set_target_properties(CryptoToys PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS CryptoToys
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(CryptoToys)
endif()
