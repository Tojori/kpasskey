# SPDX-License-Identifier: LGPL-2.1-or-later
# Build with: CC=clang CXX=clang++ cmake -B build-fuzz -DKPASSKEY_FUZZ=ON -DKPASSKEY_BUILD_DAEMON=OFF -DBUILD_TESTING=OFF
foreach(target fuzz_authenticator fuzz_ctaphid fuzz_record)
    add_executable(${target} ${target}.cpp)
    target_include_directories(${target} PRIVATE ${PROJECT_SOURCE_DIR}/tests)
    target_link_libraries(${target} PRIVATE kpasskeycore)
    target_compile_options(${target} PRIVATE -fsanitize=fuzzer)
    target_link_options(${target} PRIVATE -fsanitize=fuzzer)
endforeach()
