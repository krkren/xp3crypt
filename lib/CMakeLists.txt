# The engine-free part of xp3crypt, as two static libraries:
#
#   xp3crypt_core  the cipher and the key slot (crypt.cpp + Monocypher). The plugin needs only
#                  this; it has no file-system or zlib dependency.
#   xp3crypt_lib   the whole library: xp3crypt_core plus the XP3 writer and a random-key source,
#                  for packaging tools (the CLI, and a game's own tool such as kagex-release).
#
# Both are usable from a parent build with add_subdirectory(xp3crypt/lib).

add_library(xp3crypt_core STATIC
	crypt.cpp
	read.cpp
	monocypher/monocypher.c)
target_include_directories(xp3crypt_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(xp3crypt_core PUBLIC cxx_std_17)
set_target_properties(xp3crypt_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(XP3CRYPT_SANITIZE)
	target_compile_options(xp3crypt_core PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
	target_link_options(xp3crypt_core PUBLIC -fsanitize=address,undefined)
endif()

add_library(xp3crypt_lib STATIC
	slot.cpp
	xp3.cpp
	crypt_random.cpp)
target_link_libraries(xp3crypt_lib PUBLIC xp3crypt_core)
set_target_properties(xp3crypt_lib PROPERTIES POSITION_INDEPENDENT_CODE ON)

find_package(ZLIB)
if(ZLIB_FOUND)
	target_compile_definitions(xp3crypt_lib PRIVATE XP3CRYPT_HAVE_ZLIB)
	target_link_libraries(xp3crypt_lib PUBLIC ZLIB::ZLIB)
endif()
