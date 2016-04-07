cmake_minimum_required ( VERSION 3.1 FATAL_ERROR )
cmake_policy ( VERSION 3.1 )
project ( obexpushd
  VERSION 0.11.3
  LANGUAGES C
)

list ( APPEND CMAKE_MODULE_PATH
  ${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules
)

include ( MaintainerMode )
set ( CMAKE_C_STANDARD 99 )
set ( CMAKE_C_STANDARD_REQUIRED TRUE )
add_definitions ( -D_GNU_SOURCE )

if ( NOT CMAKE_BUILD_TYPE )
  set ( CMAKE_BUILD_TYPE Release
        CACHE STRING "Choice of a predefined CMake ruleset" FORCE )
endif ( NOT CMAKE_BUILD_TYPE )

if ( NOT MANPAGE_INSTALL_DIR )
  set ( MANPAGE_INSTALL_DIR "share/man"
    CACHE PATH "Where documentation files are copied to on installation" FORCE )
endif ( NOT MANPAGE_INSTALL_DIR )
if ( NOT DOCUMENTATION_INSTALL_DIR )
  set ( DOCUMENTATION_INSTALL_DIR "share/doc/${PROJECT_NAME}"
    CACHE PATH "Where documentation files are copied to on installation" FORCE )
endif ( NOT DOCUMENTATION_INSTALL_DIR )

add_subdirectory ( src )
add_subdirectory ( doc )

install (
  FILES       README LICENSE GPLv2.txt
  DESTINATION "${DOCUMENTATION_INSTALL_DIR}"
  PERMISSIONS OWNER_READ OWNER_WRITE
              GROUP_READ
              WORLD_READ
)

#
# Settings for CPack
#
set ( CPACK_PACKAGE_DESCRIPTION_SUMMARY "ObexPush Server" )
set ( CPACK_PACKAGE_VENDOR "Hendrik Sattler" )
set ( CPACK_PACKAGE_CONTACT "Hendrik Sattler <post@hendrik-sattler.de>" )
set ( CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README" )

set ( CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE" )
set ( CPACK_RESOURCE_FILE_README  "${CMAKE_CURRENT_SOURCE_DIR}/README" )

#setting only CPACK_PACKAGE_VERSION does not work (cmake-2.4.5)
set ( CPACK_PACKAGE_VERSION_MAJOR "${obexpushd_VERSION_MAJOR}" )
set ( CPACK_PACKAGE_VERSION_MINOR "${obexpushd_VERSION_MINOR}" )
set ( CPACK_PACKAGE_VERSION_PATCH "${obexpushd_VERSION_PATCH}" )
set ( CPACK_PACKAGE_VERSION       "${obexpushd_VERSION}" )

#the compiler may have a better idea of what the target is
if ( CMAKE_COMPILER_IS_GNUCC )
  execute_process (
    COMMAND         ${CMAKE_C_COMPILER} -dumpmachine
    OUTPUT_VARIABLE CPACK_SYSTEM_NAME
  )
  string ( REGEX REPLACE "[\r\n]" "" CPACK_SYSTEM_NAME ${CPACK_SYSTEM_NAME} )
else ( CMAKE_COMPILER_IS_GNUCC )
  set ( CPACK_SYSTEM_NAME "${CMAKE_SYSTEM_NAME}" )
endif ( CMAKE_COMPILER_IS_GNUCC )

set ( CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}" )

#different cpack generators need different package names
set ( CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_FILE_NAME}-source" )
set ( CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_FILE_NAME}_${CPACK_SYSTEM_NAME}" )

if ( UNIX )
    set ( CPACK_GENERATOR "TGZ" )
    set ( CPACK_SOURCE_GENERATOR "TGZ" )
endif ( UNIX )
set ( CPACK_SOURCE_IGNORE_FILES
  "~$"
  "/\\\\.git/"
  "/build/"
)

# this must _follow_ the settings!
include ( CPack )
