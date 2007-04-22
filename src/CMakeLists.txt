#TODO: Replace with FindPkgConfig as soon as it is available
#      in a CMake release

include ( UsePkgConfig )

pkgconfig ( openobex
  OPENOBEX_INCLUDE_DIR
  OPENOBEX_LINK_DIR
  OPENOBEX_LINK_FLAGS
  OPENOBEX_CFLAGS
)
pkgconfig ( bluez
  BLUEZ_INCLUDE_DIR
  BLUEZ_LINK_DIR
  BLUEZ_LINK_FLAGS
  BLUEZ_CFLAGS
)
foreach ( i OPENOBEX BLUEZ )
  #hack around buggy CMake module: remove newlines
  foreach ( k  INCLUDE_DIR LINK_DIR LINK_FLAGS CFLAGS )
    string ( REGEX REPLACE "[\r\n]" "" ${i}_${k} ${${i}_${k}} )
  endforeach ( k  INCLUDE_DIR LINK_DIR LINK_FLAGS CFLAGS )
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

#if that ever makes it to upstream
check_function_exists ( OBEX_DebugSet OBEX_NEWDEBUG )
if ( OBEX_NEWDEBUG )
  add_definitions ( -DOPENOBEX_NEWDEBUG=1 )
endif ( OBEX_NEWDEBUG )

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
  LINK_FLAGS "${OPENOBEX_LINK_FLAGS} ${BLUEZ_LINK_FLAGS}"
)

INSTALL (
  TARGETS obexpushd
  RUNTIME DESTINATION bin
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
              GROUP_READ             GROUP_EXECUTE
	      WORLD_READ             WORLD_EXECUTE
)
