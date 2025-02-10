cmake_minimum_required (VERSION 3.10)
project (libftp++ DESCRIPTION "A client ftp library")

if(CMAKE_BUILD_TYPE)
    message("Building ${CMAKE_BUILD_TYPE} build.")
elseif(NOT CMAKE_BUILD_TYPE)
    message(FATAL_ERROR "No build type specified. Use -DCMAKE_BUILD_TYPE=[DEBUG|RELEASE] to specify.")
endif(CMAKE_BUILD_TYPE)

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
if(NOT NOSSL)
    if(APPLE)
        set(LIBS ssl crypto)
    elseif(UNIX)
        set(LIBS ssl)
    else()
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNOSSL")
        set(LIBS "")
    endif()
else()
    set(LIBS "")
endif()

# where the library will be built to
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/libs)

add_library(objlib OBJECT ${LIBFTPPP_SOURCES} ${LIBFTPPP_HEADERS})
# shared libraries need PIC
set_property(TARGET objlib PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library(libstatic STATIC $<TARGET_OBJECTS:objlib>)
set_target_properties(libstatic PROPERTIES OUTPUT_NAME ftp++)

add_library(libftp++ SHARED $<TARGET_OBJECTS:objlib>)
set_target_properties(libftp++ PROPERTIES OUTPUT_NAME ftp++)

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
if(CMAKE_BUILD_TYPE MATCHES "Release")
	# adds the 'make install' targets to copy the shared library to /usr/local/lib/ directory
	install(TARGETS libftp++ DESTINATION ${CMAKE_INSTALL_LIBDIR} )
	# adds all the relevant headers to /usr/local/include/gphoto2pp when ``make install`` is executed
	install(FILES ${LIBFTPPP_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libftp++)
	# install the pkg-config config to system folder
#	install(FILES ${CMAKE_BINARY_DIR}/linenoise.pc DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)
endif(CMAKE_BUILD_TYPE MATCHES "Release")

########################################################################################################################
# Unit Tests
########################################################################################################################
# for now only add unit tests in dev mode
if (CMAKE_BUILD_TYPE MATCHES "Debug")
	enable_testing ()
	add_subdirectory (tests)
else (CMAKE_BUILD_TYPE MATCHES "Debug")
    message ("Skipping unit tests in ${CMAKE_BUILD_TYPE} build.")
endif (CMAKE_BUILD_TYPE MATCHES "Debug")