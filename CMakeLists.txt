cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

if(APPLE)
     if(NOT CMAKE_OSX_DEPLOYMENT_TARGET)
        set(CMAKE_OSX_DEPLOYMENT_TARGET "10.12" CACHE STRING "" FORCE)
    endif()
endif()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" OCGUI_RELEASE_VERSION LIMIT_COUNT 1)
project(openconnect-gui
    VERSION ${OCGUI_RELEASE_VERSION}
    HOMEPAGE_URL https://github.com/icelol/openconnect-gui-killswitch
    LANGUAGES CXX
)

message(STATUS "Building ${PROJECT_NAME} v${PROJECT_VERSION} [cmake]")
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    # Avoid embedding a developer's local home/source path in release binaries.
    add_compile_options("-ffile-prefix-map=${CMAKE_SOURCE_DIR}=.")
endif()

# The SHORT and COMPANY names affect the installation directory.
set(PRODUCT_NAME_SHORT "OpenConnect-GUI-KillSwitch")
set(PRODUCT_NAME_COMPANY "OpenConnect-GUI Team")
set(PRODUCT_NAME_COMPANY_DOMAIN "gui.openconnect-vpn.net")
set(INTERNAL_PROJECT_VERSION "${PROJECT_VERSION}")

# The long name is used as the installer description
# and About screen description.
set(PRODUCT_NAME_LONG "OpenConnect VPN + Kill Switch")

# Printed in the About screen
set(PRODUCT_NAME_COPYRIGHT_SHORT "Copyright © 2016-2024 Red Hat Inc., Nikos Mavrogiannopoulos, Ľubomír Carik and others")
set(PRODUCT_NAME_COPYRIGHT_FULL "Copyright © 2014-2015 Red Hat Inc.<br>Copyright © 2016-2024 Nikos Mavrogiannopoulos<br>Copyright © 2016-2024 Ľubomír Carik<br>Copyright © 2020-2024 David Woodhouse<br>Copyright © 2021-2024 Dimitri Papadopoulos Orfanos<br>Copyright © 2023-2024 Marios Paouris")

# The application name / main window title / installer app name
set(APP_NAME "OpenConnect VPN + Kill Switch")
# The URL for determining the latest release
set(GITLAB_LATEST_RELEASE_URL "https://api.github.com/repos/icelol/openconnect-gui-killswitch/releases/latest")
# The URL for the latest release
set(APP_RELEASES_URL "https://github.com/icelol/openconnect-gui-killswitch/releases")
# The URL for downloading the latest release
set(APP_DOWNLOAD_WIN_URL "${APP_RELEASES_URL}")

set(APP_ISSUES_URL "https://github.com/icelol/openconnect-gui-killswitch/issues")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/CMake/Modules/")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/CMake/Includes/")

set(SIGN_EXE "false" CACHE STRING "When set to true the executable will be signed")

include(ProjectSettings)
option(OCGUI_SYSTEM_DEPS "Use native package-manager dependencies on Windows" OFF)
include(ProjectDependencies)
include(CheckCXXSymbolExists)
set(CMAKE_REQUIRED_INCLUDES ${OPENCONNECT_INCLUDE_DIRS})
set(CMAKE_REQUIRED_LIBRARIES ${OPENCONNECT_LINK_LIBRARIES})
unset(OCGUI_HAVE_TLS12_API CACHE)
if(WIN32)
    check_cxx_symbol_exists(openconnect_set_tls12_only "winsock2.h;openconnect.h" OCGUI_HAVE_TLS12_API)
else()
    check_cxx_symbol_exists(openconnect_set_tls12_only "openconnect.h" OCGUI_HAVE_TLS12_API)
endif()
if(OCGUI_SYSTEM_DEPS AND NOT OCGUI_HAVE_TLS12_API)
    message(FATAL_ERROR "Build the pinned patched OpenConnect library with scripts/build-openconnect.sh first")
endif()
unset(CMAKE_REQUIRED_INCLUDES)
unset(CMAKE_REQUIRED_LIBRARIES)

if(MINGW)
    # FIXME: upgrading CMake from 3.15 to newer version fails on packaging
    # because objdump.exe is not supported (actually the exe suffix break it)
    # TODO: bundling dependencies use CMake deprecated function; need update..
    find_program(CMAKE_OBJDUMP NAMES objdump.exe)
    string(REGEX REPLACE "\\.exe$" "" CMAKE_OBJDUMP ${CMAKE_OBJDUMP})

endif()

add_subdirectory(src)

include(CTest)
if(BUILD_TESTING AND (APPLE OR WIN32))
    add_subdirectory(tests)
endif()

install(FILES LICENSE.txt
    DESTINATION .
    COMPONENT App
)

include(clang-format)
include(git_revision_main)
include(build_timestamp_main)

include(ProjectPackage)

