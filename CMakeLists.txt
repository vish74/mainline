project ( obexpushd C )

set ( VERSION_MAJOR 0 )
set ( VERSION_MINOR 7 )
set ( VERSION_PATCH 0 )
set ( VERSION "${VERSION_MAJOR}.${VERSION_MINOR}" )
if ( VERSION_PATCH GREATER 0 )
  set ( VERSION "${VERSION}.${VERSION_PATCH}" )
endif ( VERSION_PATCH GREATER 0 )

cmake_minimum_required ( VERSION 2.4.7 )

if ( NOT CMAKE_BUILD_TYPE )
  set ( CMAKE_BUILD_TYPE Release
        CACHE STRING "Choice of a predefined CMake ruleset" FORCE )
endif ( NOT CMAKE_BUILD_TYPE )

add_subdirectory ( src )

if ( NOT DOCUMENTS_DIRECTORY )
  set ( DOCUMENTS_DIRECTORY "share/doc/${PROJECT_NAME}"
        CACHE PATH "Where documentation files are copied to on installation" FORCE )
endif ( NOT DOCUMENTS_DIRECTORY )

add_subdirectory ( doc )

install (
  FILES       README LICENSE GPLv2.txt
  DESTINATION "${DOCUMENTS_DIRECTORY}"
  PERMISSIONS OWNER_READ OWNER_WRITE
              GROUP_READ
              WORLD_READ
)

#
# Settings for CPack
#
set ( CPACK_PACKAGE_DESCRIPTION_SUMMARY "ObexPush Server" )
set ( CPACK_PACKAGE_VENDOR "Hendrik Sattler" )
set ( CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README" )

set ( CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE" )
set ( CPACK_RESOURCE_FILE_README  "${CMAKE_CURRENT_SOURCE_DIR}/README" )

#setting only CPACK_PACKAGE_VERSION does not work (cmake-2.4.5)
set ( CPACK_PACKAGE_VERSION_MAJOR "${VERSION_MAJOR}" )
set ( CPACK_PACKAGE_VERSION_MINOR "${VERSION_MINOR}" )
set ( CPACK_PACKAGE_VERSION_PATCH "${VERSION_PATCH}" )
set ( CPACK_PACKAGE_VERSION       "${VERSION}" )

execute_process (
  COMMAND         ${CMAKE_C_COMPILER} -dumpmachine
  OUTPUT_VARIABLE CPACK_SYSTEM_NAME
)
string ( REGEX REPLACE "[\r\n]" "" CPACK_SYSTEM_NAME ${CPACK_SYSTEM_NAME} )

#fix a messed-up cmake default value for package naming
set ( CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}" )
if ( CPACK_SYSTEM_NAME )
    set ( CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_FILE_NAME}_${CPACK_SYSTEM_NAME}" )
endif ( CPACK_SYSTEM_NAME )
set ( CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}-source" )

if ( UNIX )
    set ( CPACK_GENERATOR "TGZ" )
    set ( CPACK_SOURCE_GENERATOR "TGZ" )
endif ( UNIX )
set ( CPACK_SOURCE_IGNORE_FILES
  "~$"
  "/\\\\.svn/"
  "/build/"
)

# this must _follow_ the settings!
include ( CPack )
