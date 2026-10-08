# SPDX-License-Identifier: LGPL-2.1-or-later
cmake_minimum_required(VERSION 3.22)
project(kpasskey VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

option(BUILD_TESTING "Build tests" ON)
option(KPASSKEY_BUILD_DAEMON "Build the daemon (needs KF6Wallet, PolkitQt6-1, Widgets)" ON)
option(KPASSKEY_FUZZ "Build libFuzzer targets (clang only; implies ASan/UBSan)" OFF)
option(KPASSKEY_SANITIZE "Build everything with ASan + UBSan" OFF)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core DBus)
find_package(OpenSSL 3.0 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(TSS2_MU REQUIRED IMPORTED_TARGET tss2-mu)

add_compile_definitions(
    QT_NO_CAST_FROM_ASCII
    QT_NO_CAST_TO_ASCII
    QT_NO_KEYWORDS
    KPASSKEY_VERSION="${PROJECT_VERSION}"
    TRANSLATION_DOMAIN="kpasskey"
)
add_compile_options(-Wall -Wextra -Wformat=2 -fstack-protector-strong -fstack-clash-protection
                    $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=3>)
add_link_options(-Wl,-z,relro,-z,now)
if(KPASSKEY_SANITIZE OR KPASSKEY_FUZZ)
    add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()
if(KPASSKEY_FUZZ)
    # instrument the library under test as well
    add_compile_options(-fsanitize=fuzzer-no-link)
endif()

# --- core: CTAP2 engine, credential model, crypto wrapper (no GUI, no KWallet) ---
add_library(kpasskeycore STATIC
    src/core/authenticator.cpp
    src/core/credential.cpp
    src/core/credential_store.cpp
    src/core/crypto.cpp
    src/core/logging.cpp
    src/core/pin_uv.cpp
    src/core/hardware_keys.cpp
    src/core/cxf.cpp
    src/core/backup.cpp
    src/hid/ctaphid.cpp
)
target_include_directories(kpasskeycore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(kpasskeycore PUBLIC Qt6::Core OpenSSL::Crypto PkgConfig::TSS2_MU)
set_target_properties(kpasskeycore PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(KPASSKEY_BUILD_DAEMON)
    find_package(Qt6 REQUIRED COMPONENTS Widgets Network)
    pkg_check_modules(SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
    find_package(KF6Wallet REQUIRED)
    find_package(KF6I18n REQUIRED)
    find_package(PolkitQt6-1 REQUIRED)

    add_executable(kpasskeyd
        src/daemon/main.cpp
        src/daemon/manager_dbus.cpp
        src/daemon/session_watcher.cpp
        src/hid/uhid_device.cpp
        src/hid/helper_device.cpp
        src/hid/hid_transport.h
        src/tpm/tpm_client.cpp
        src/kwallet/kwallet_store.cpp
        src/ui/presence_dialog.cpp
        src/ui/backup_dialogs.cpp
        src/verification/polkit_verifier.cpp
    )
    target_link_libraries(kpasskeyd PRIVATE
        kpasskeycore Qt6::Widgets Qt6::DBus Qt6::Network KF6::Wallet KF6::I18n PolkitQt6-1::Core)

    # Minimal, Qt-free helper that alone may open /dev/uhid (see docs/security.md T15)
    add_executable(kpasskey-uhid-helper src/helper/uhid_helper.cpp)
    target_include_directories(kpasskey-uhid-helper PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(kpasskey-uhid-helper PRIVATE PkgConfig::SYSTEMD)

    # TPM 2.0 key helper: the only component with TPM access (docs/security.md T5/T6)
    pkg_check_modules(TSS2 REQUIRED IMPORTED_TARGET tss2-esys tss2-tctildr tss2-mu)
    add_executable(kpasskey-tpm-helper src/helper/tpm_helper.cpp)
    target_include_directories(kpasskey-tpm-helper PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(kpasskey-tpm-helper PRIVATE PkgConfig::SYSTEMD PkgConfig::TSS2)

    include(GNUInstallDirs)
    install(TARGETS kpasskeyd kpasskey-uhid-helper kpasskey-tpm-helper DESTINATION ${CMAKE_INSTALL_LIBEXECDIR})
    configure_file(data/kpasskey-uhid@.service.in ${CMAKE_CURRENT_BINARY_DIR}/kpasskey-uhid@.service @ONLY)
    configure_file(data/kpasskey-tpm@.service.in ${CMAKE_CURRENT_BINARY_DIR}/kpasskey-tpm@.service @ONLY)
    install(FILES data/kpasskey-uhid.socket ${CMAKE_CURRENT_BINARY_DIR}/kpasskey-uhid@.service
                  data/kpasskey-tpm.socket ${CMAKE_CURRENT_BINARY_DIR}/kpasskey-tpm@.service
            DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
    install(FILES data/kpasskey-sysusers.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/sysusers.d RENAME kpasskey.conf)
    install(FILES data/kpasskey-tmpfiles.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/tmpfiles.d RENAME kpasskey.conf)
    install(FILES packaging/udev/70-kpasskey-uhid.rules DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/udev/rules.d)
    install(FILES data/org.kde.kpasskey.policy DESTINATION ${CMAKE_INSTALL_DATADIR}/polkit-1/actions)
    configure_file(data/kpasskeyd.service.in ${CMAKE_CURRENT_BINARY_DIR}/kpasskeyd.service @ONLY)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/kpasskeyd.service DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/user)
endif()

if(KPASSKEY_FUZZ)
    add_subdirectory(fuzz)
endif()

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()
