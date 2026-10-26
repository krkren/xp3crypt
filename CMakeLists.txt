# xp3crypt: the plugin, the library, the CLI and their tests, built on their own. The engine
# build takes the plugin from plugin/ instead (TVP_PLUGIN_FOLDERS / TVP_PLUGINS_STATIC).
#
# Building the plugin needs a krkrz_dev checkout for tp_stub and ncbind:
#
#   cmake -B build -DKRKRZ_DEV_DIR=/path/to/krkrz_dev && cmake --build build && ctest --test-dir build
#
# Without one, build just the library, CLI and tests with -DXP3CRYPT_PLUGIN=OFF.
cmake_minimum_required(VERSION 3.16)
project(xp3crypt_repo C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(XP3CRYPT_PLUGIN "Build the plugin (needs krkrz_dev)" ON)
option(XP3CRYPT_SANITIZE "Build with AddressSanitizer and UBSan" OFF)

set(KRKRZ_DEV_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../krkrz_dev CACHE PATH "A krkrz_dev checkout (for tp_stub and ncbind)")
set(TPSTUB_DIR ${KRKRZ_DEV_DIR}/src/plugins/tp_stub CACHE PATH "Path to tp_stub")
set(NCBIND_DIR ${KRKRZ_DEV_DIR}/src/plugins/ncbind CACHE PATH "Path to ncbind")
set(KRKRZ_VARIANT SDL CACHE STRING "The engine's build variant (SDL, WIN, LIB)")

# The engine-free library (cipher, key slot, XP3 writer, random keys)
add_subdirectory(lib)

if(XP3CRYPT_PLUGIN)
	if(NOT EXISTS ${TPSTUB_DIR}/tp_stub.h)
		message(FATAL_ERROR "No tp_stub at ${TPSTUB_DIR}: set KRKRZ_DEV_DIR to a krkrz_dev checkout, or -DXP3CRYPT_PLUGIN=OFF")
	endif()
	add_subdirectory(plugins/xp3crypt)
endif()

# The CLI (target name differs from the plugin target "xp3crypt"; the program is still xp3crypt)
add_executable(xp3crypt_cli tools/xp3crypt.cpp)
set_target_properties(xp3crypt_cli PROPERTIES OUTPUT_NAME xp3crypt)
target_link_libraries(xp3crypt_cli PRIVATE xp3crypt_lib)

# Tests
enable_testing()
add_executable(crypt_test tests/crypt_test.cpp)
target_link_libraries(crypt_test PRIVATE xp3crypt_lib)
add_test(NAME crypt_test COMMAND crypt_test)

add_executable(xp3_test tests/xp3_test.cpp)
target_link_libraries(xp3_test PRIVATE xp3crypt_lib)
add_test(NAME xp3_test COMMAND xp3_test)

add_executable(hash_test tests/hash_test.cpp)
target_link_libraries(hash_test PRIVATE xp3crypt_lib)
add_test(NAME hash_test COMMAND hash_test)
