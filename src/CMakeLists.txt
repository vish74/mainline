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
  add_definitions ( -DOPENOBEX_TCPOBEX=1 )
endif ( OpenObex_HAVE_TcpObex )

option ( USE_SPAWN "Use POSIX spawn function instead of fork+exec" ON )
if ( USE_SPAWN )
  add_definitions ( -DUSE_SPAWN )
endif ( USE_SPAWN )

option ( USE_THREADS "Use POSIX threads instead of fork (if supported by system)" ON )
if ( USE_THREADS )
  find_package ( Threads )
  if ( CMAKE_USE_PTHREADS_INIT )
    add_definitions ( -DUSE_THREADS )
    find_library ( THREAD_LIBRARY pthread )
    mark_as_advanced ( THREAD_LIBRARY )
  endif ( CMAKE_USE_PTHREADS_INIT )
endif ( USE_THREADS )

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
if ( OpenObex_HAVE_TcpObex )
  list ( APPEND SOURCES net/tcpobex.c )
else ( OpenObex_HAVE_TcpObex )
  list ( APPEND SOURCES net/inobex.c )
endif ( OpenObex_HAVE_TcpObex )

add_executable ( obexpushd ${SOURCES} )
target_link_libraries ( obexpushd
  ${OpenObex_LIBRARIES}
  ${Bluetooth_LIBRARIES}
  ${THREAD_LIBRARY}
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
