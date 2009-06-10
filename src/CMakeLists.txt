#
# ObexPush server daemon
#
list ( APPEND SOURCES
  obexpushd.c
  obex_auth.c
  md5.c
  checks.c
  utf.c
  action/core.c
  action/connect.c
  action/disconnect.c
  action/get.c
  action/put.c
  io/core.c
  io/pipe.c
  net/auth.c
  net/core.c
  net/btobex.c
  net/publish/sdp.c
  net/irobex.c
)

set ( OBEXPUSHD_VERSION ${VERSION} )
configure_file (
  ${CMAKE_CURRENT_SOURCE_DIR}/version.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/version.h
)

foreach ( i Bluetooth OpenObex )
  find_package ( ${i} REQUIRED )
  include_directories ( ${${i}_INCLUDE_DIRS} )
endforeach ( i )

include_directories (
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

if ( OpenObex_HAVE_TcpObex )
  list ( APPEND obexpushd_DEFINITIONS OPENOBEX_TCPOBEX=1 )
  list ( APPEND SOURCES net/tcpobex.c )
else ( OpenObex_HAVE_TcpObex )
  list ( APPEND SOURCES net/inobex.c )
endif ( OpenObex_HAVE_TcpObex )

option ( USE_SPAWN "Use POSIX spawn function instead of fork+exec" ON )
if ( USE_SPAWN )
  list ( APPEND obexpushd_DEFINITIONS USE_SPAWN )
endif ( USE_SPAWN )

option ( USE_THREADS "Use POSIX threads instead of fork (if supported by system)" ON )
if ( USE_THREADS )
  find_package ( Threads )
  if ( CMAKE_USE_PTHREADS_INIT )
    list ( APPEND obexpushd_DEFINITIONS USE_THREADS )
    find_library ( THREAD_LIBRARY pthread )
    mark_as_advanced ( THREAD_LIBRARY )
  endif ( CMAKE_USE_PTHREADS_INIT )
endif ( USE_THREADS )

#option ( ENABLE_AVAHI "Use the avahi-client library to publish the service" OFF )
#if ( ENABLE_AVAHI )
#  find_package ( AvahiClient )
#endif ( ENABLE_AVAHI )
#if ( AvahiClient_FOUND )
#  include_directories ( ${AvahiClient_INCLUDE_DIRS} )
#  list ( APPEND obexpushd_DEFINITIONS ENABLE_AVAHI )
#  list ( APPEND SOURCES net/publish/avahi.c )
#endif ( AvahiClient_FOUND )

option ( ENABLE_TCPWRAP "Use the tcp wrapper library to check for restrictions on incoming connections" ON )
if ( ENABLE_TCPWRAP )
  find_package ( TcpWrap )
endif ( ENABLE_TCPWRAP )
if ( TcpWrap_FOUND )
  include_directories ( ${TcpWrap_INCLUDE_DIRS} )
  list ( APPEND obexpushd_DEFINITIONS ENABLE_TCPWRAP )
endif ( TcpWrap_FOUND )

add_executable ( obexpushd ${SOURCES} )
target_link_libraries ( obexpushd
  ${OpenObex_LIBRARIES}
  ${Bluetooth_LIBRARIES}
  ${THREAD_LIBRARY}
)
#if ( AvahiClient_FOUND )
#  target_link_libraries ( obexpushd
#    ${AvahiClient_LIBRARIES}
#  )
#endif ( AvahiClient_FOUND )
if ( TcpWrap_FOUND )
  target_link_libraries ( obexpushd
    ${TcpWrap_LIBRARIES}
  )
endif ( TcpWrap_FOUND )

set_property ( TARGET obexpushd PROPERTY
  COMPILE_DEFINITIONS ${obexpushd_DEFINITIONS}
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
