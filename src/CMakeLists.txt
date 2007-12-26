set ( OBEXPUSHD_VERSION ${VERSION} )
configure_file (
  ${CMAKE_CURRENT_SOURCE_DIR}/version.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/version.h
)

find_package ( PkgConfig )
foreach ( i openobex bluez )
  pkg_check_modules ( ${i} REQUIRED ${i} )
  include_directories ( ${${i}_INCLUDE_DIRS} )
  link_directories ( ${${i}_LIBRARY_DIRS} )
endforeach ( i )

include_directories (
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

include ( CheckFunctionExists )
message( STATUS "Checking capabilities of OpenObex..." )
set ( CMAKE_REQUIRED_FLAGS ${openobex_CFLAGS} )
set ( CMAKE_REQUIRED_DEFINITIONS )
set ( CMAKE_REQUIRED_INCLUDES ${openobex_INLUDE_DIRS} )
set ( CMAKE_REQUIRED_LIBRARIES ${openobex_LDFLAGS} )
check_function_exists ( TcpOBEX_ServerRegister USE_TCPOBEX )
if ( USE_TCPOBEX )
  add_definitions ( -DOPENOBEX_TCPOBEX=1 )
endif ( USE_TCPOBEX )

#
# ObexPush server daemon
#
list ( APPEND SOURCES
  obexpushd.c
  obexpush-sdp.c
  obex_auth.c
  md5.c
  data_io.c
  put.c
  get.c
  checks.c
  utf.c
  net/auth.c
  net/core.c
  net/btobex.c
  net/irobex.c
)
if ( USE_TCPOBEX )
  list ( APPEND SOURCES net/tcpobex.c )
else ( USE_TCPOBEX )
  list ( APPEND SOURCES net/inobex.c )
endif ( USE_TCPOBEX )

add_executable ( obexpushd ${SOURCES} )
target_link_libraries ( obexpushd
  ${openobex_LIBRARIES}
  ${bluez_LIBRARIES}
)
set_target_properties ( obexpushd PROPERTIES
  COMPILE_FLAGS "${openobex_CFLAGS_OTHERS} ${bluez_CFLAGS_OTHERS}"
  LINK_FLAGS "${openobex_LDFLAGS_OTHERS} ${bluez_LDFLAGS_OTHERS}"
)
install (
  TARGETS obexpushd
  RUNTIME DESTINATION bin
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
              GROUP_READ             GROUP_EXECUTE
	      WORLD_READ             WORLD_EXECUTE
)

set ( CPACK_PACKAGE_EXECUTABLES "obexpushd" )
if ( UNIX )
    set ( CPACK_STRIP_FILES "bin/obexpushd" )
endif ( UNIX )
