cmake_minimum_required (VERSION 3.10)
project (LIBFTPPP DESCRIPTION "A client ftp library")

# Configuration specific to being the main project
if(PROJECT_NAME STREQUAL CMAKE_PROJECT_NAME)
    set(CMAKE_VERBOSE_MAKEFILE ON)
    set(LIBFTPPP_NOT_SUBPROJECT ON)
endif(PROJECT_NAME STREQUAL CMAKE_PROJECT_NAME)

if(CMAKE_BUILD_TYPE)
    message("Building ${PROJECT_NAME} in ${CMAKE_BUILD_TYPE} build.")
elseif(NOT CMAKE_BUILD_TYPE)
    message(FATAL_ERROR "No build type specified. Use -DCMAKE_BUILD_TYPE=[DEBUG|RELEASE] to specify.")
endif(CMAKE_BUILD_TYPE)

option(FTPLIBPP_BUILD_TESTS "Build ftplibpp tests." Off)
option(FTPLIBPP_NOSSL "Disable SSL library support." Off)

find_package(Sanitizers)
if(Sanitizers_FOUND)
    message(STATUS "Sanitizers found, using settings:")
    message(STATUS "\tSANITIZE_ADDRESS   : ${SANITIZE_ADDRESS}")
    message(STATUS "\tSANITIZE_MEMORY    : ${SANITIZE_MEMORY}")
    message(STATUS "\tSANITIZE_THREAD    : ${SANITIZE_THREAD}")
    message(STATUS "\tSANITIZE_UNDEFINED : ${SANITIZE_UNDEFINED}")
endif(Sanitizers_FOUND)
# set the version of our library
# MAJOR, is significant breaking changes
# MINOR, is when we might have changed signatures of existing functions
# PATCH, is just bug fixes and no breaking changes
set(LIBFTPPP_VERSION_MAJOR 2)
set(LIBFTPPP_VERSION_MINOR 0)
set(LIBFTPPP_VERSION_PATCH 5)
set(LIBFTPPP_VERSION_STRING ${LIBFTPPP_VERSION_MAJOR}.${LIBFTPPP_VERSION_MINOR}.${LIBFTPPP_VERSION_PATCH})

file(GLOB LIBFTPPP_SOURCE_FILES ftplib.cpp)
file(GLOB LIBFTPPP_HEADER_FILES ftplib.h)

set(LIBFTPPP_SOURCES ${LIBFTPPP_SOURCE_FILES})
set(LIBFTPPP_HEADERS ${LIBFTPPP_HEADER_FILES})

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fPIC -D_REENTRANT")

if(NOT FTPLIBPP_NOSSL)
    if(APPLE)
        set(LIBS ssl crypto)
    elseif(UNIX)
        set(LIBS ssl)
    else(UNIX)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNOSSL")
        set(LIBS "")
    endif(APPLE)
else(NOT FTPLIBPP_NOSSL)
    set(LIBS "")
endif(NOT FTPLIBPP_NOSSL)

# where the library will be built to
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/libs)

add_library(objlib OBJECT ${LIBFTPPP_SOURCES} ${LIBFTPPP_HEADERS})
# shared libraries need PIC
set_property(TARGET objlib PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library(libstatic STATIC $<TARGET_OBJECTS:objlib>)
set_target_properties(libstatic PROPERTIES OUTPUT_NAME ftp++)

add_library(libftp++ SHARED $<TARGET_OBJECTS:objlib>)
set_target_properties(libftp++ PROPERTIES OUTPUT_NAME ftp++)
if(Sanitizers_FOUND)
    add_sanitizers(libftp++)
endif(Sanitizers_FOUND)

# Link libraries for the shared library
target_link_libraries(libftp++ PUBLIC ${LIBS})

target_include_directories(libftp++ PUBLIC ".")
# sets the shared library version
# http://cmake.3232098.n2.nabble.com/Version-in-name-of-shared-library-td7581530.html
set_target_properties(libftp++ PROPERTIES VERSION ${LIBFTPPP_VERSION_STRING} SOVERSION ${LIBFTPPP_VERSION_MAJOR})
# set_target_properties(libftp++ PROPERTIES LINKER_LANGUAGE CPP)

# create pkg-config files for configuration in non-cmake projects
# configure_file(linenoise.pc.in linenoise.pc @ONLY)

# only offer install option if they compiled with release mode
if(CMAKE_BUILD_TYPE MATCHES "^(RELEASE|Release)")
	# adds the 'make install' targets to copy the shared library to /usr/local/lib/ directory
	install(TARGETS libftp++ DESTINATION ${CMAKE_INSTALL_LIBDIR} )
	# adds all the relevant headers to /usr/local/include/gphoto2pp when ``make install`` is executed
	install(FILES ${LIBFTPPP_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libftp++)
	# install the pkg-config config to system folder
#	install(FILES ${CMAKE_BINARY_DIR}/linenoise.pc DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)
endif(CMAKE_BUILD_TYPE MATCHES "^(RELEASE|Release)")

########################################################################################################################
# Unit Tests
########################################################################################################################
if (FTPLIBPP_BUILD_TESTS)
	enable_testing ()
	add_subdirectory (tests)
else (FTPLIBPP_BUILD_TESTS)
    message (STATUS "Skipping unit tests in ${CMAKE_BUILD_TYPE} build.")
endif (FTPLIBPP_BUILD_TESTS)