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
include_directories (
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${OPENOBEX_INCLUDE_DIR}
  ${BLUEZ_INCLUDE_DIR}
)
link_directories (
  ${OPENOBEX_LINK_DIR}
  ${BLUEZ_LINK_DIR}
)
add_definitions (
  ${OPENOBEX_CFLAGS}
  ${BLUEZ_CFLAGS}
)

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
)

set ( USE_TCPOBEX OFF CACHE BOOL "Force usage of new TcpOBEX API" )
if ( USE_TCPOBEX )
  set ( SOURCES ${SOURCES} net/tcpobex.c )
  add_definitions ( -DOPENOBEX_TCPOBEX=1 )

else ( USE_TCPOBEX )
  set ( SOURCES ${SOURCES} net/inobex.c )

endif ( USE_TCPOBEX )

add_executable ( obexpushd
  ${SOURCES}
)

set_target_properties ( obexpushd PROPERTIES
  LINK_FLAGS "${OPENOBEX_LINK_FLAGS} ${BLUEZ_LINK_FLAGS}"
)
