# SPDX-License-Identifier: LGPL-2.1-or-later
find_package(Qt6 REQUIRED COMPONENTS Test)

function(kpasskey_test name source)
    add_executable(${name} ${source})
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(${name} PRIVATE kpasskeycore Qt6::Test)
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endfunction()

kpasskey_test(test_authenticator unit/test_authenticator.cpp)
kpasskey_test(test_ctaphid unit/test_ctaphid.cpp)
kpasskey_test(test_security security/test_security.cpp)

# Test-only CTAPHID-over-stdio harness for interop tests (never installed)
add_executable(stdio_harness integration/stdio_harness.cpp)
target_include_directories(stdio_harness PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(stdio_harness PRIVATE kpasskeycore)

find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    execute_process(COMMAND ${Python3_EXECUTABLE} -c "import fido2" RESULT_VARIABLE _no_fido2 OUTPUT_QUIET ERROR_QUIET)
    if(_no_fido2 EQUAL 0)
        add_test(NAME interop_python_fido2
                 COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/integration/fido2_interop.py
                         --harness $<TARGET_FILE:stdio_harness>)
    else()
        message(STATUS "python-fido2 not found: interop test disabled")
    endif()
endif()
