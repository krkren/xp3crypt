# The xp3crypt plugin. Built by the engine when this repository's plugins/ folder is in
# TVP_PLUGIN_FOLDERS (listed after krkrz_dev's plugins, whose tp_stub and ncbind it uses) and
# xp3crypt is in TVP_PLUGINS_STATIC; or on its own through the CMakeLists.txt at the top of this
# repository.
#
# The cipher and key slot come from ../../lib (crypt.cpp + Monocypher); the plugin adds no
# file-system or zlib dependency of its own.
set(TPSTUB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../tp_stub CACHE PATH "Path to tp_stub directory")
include(${TPSTUB_DIR}/krkrz.cmake)

krkrz_plugin(xp3crypt NCBIND
	SOURCES
		main.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/../../lib/crypt.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/../../lib/read.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/../../lib/monocypher/monocypher.c
	INCLUDES
		${CMAKE_CURRENT_SOURCE_DIR}/../../lib
)
target_compile_features(xp3crypt PRIVATE cxx_std_17)
