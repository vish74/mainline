#TODO: Replace with FindPkgConfig as soon as it is available
#      in a CMake release

include ( UsePkgConfig )
foreach ( i openobex bluez )
  pkgconfig ( ${i}
    ${i}_INCLUDE_DIR
    ${i}_LINK_DIR
    ${i}_LINK_FLAGS
    ${i}_CFLAGS
  )
  #hack around buggy CMake module: remove newlines
  foreach ( k INCLUDE_DIR LINK_DIR LINK_FLAGS CFLAGS )
    string ( REGEX REPLACE "[\r\n]" "" ${i}_${k} ${${i}_${k}} )
  endforeach ( k INCLUDE_DIR LINK_DIR LINK_FLAGS CFLAGS )
  include_directories ( ${${i}_INCLUDE_DIR} )
  link_directories ( ${${i}_LINK_DIR} )
  add_definitions ( ${${i}_CFLAGS} )
endforeach ( i OPENOBEX BLUEZ )

include_directories ( ${CMAKE_CURRENT_SOURCE_DIR} )

include ( CheckFunctionExists )
message( STATUS "Checking capabilities of OpenObex..." )
set ( CMAKE_REQUIRED_FLAGS ${OPENOBEX_CFLAGS} )
set ( CMAKE_REQUIRED_DEFINITIONS )
set ( CMAKE_REQUIRED_INCLUDES ${OPENOBEX_INLUDE_DIR} )
set ( CMAKE_REQUIRED_LIBRARIES ${OPENOBEX_LINK_FLAGS} )
check_function_exists ( TcpOBEX_ServerRegister USE_TCPOBEX )
if ( USE_TCPOBEX )
  set ( SOURCES ${SOURCES} net/tcpobex.c )
  add_definitions ( -DOPENOBEX_TCPOBEX=1 )
else ( USE_TCPOBEX )
  set ( SOURCES ${SOURCES} net/inobex.c )
endif ( USE_TCPOBEX )

set ( SOURCES
  obexpushd.c
  obexpush-sdp.c
  obex_auth.c
  md5.c
  data_io.c
  put.c
  get.c
  checks.c
  utf.c
  net/core.c
  net/btobex.c
  net/irobex.c
  ${SOURCES}
)

add_executable ( obexpushd
  ${SOURCES}
)

set_target_properties ( obexpushd PROPERTIES
  LINK_FLAGS "${openobex_LINK_FLAGS} ${bluez_LINK_FLAGS}"
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
