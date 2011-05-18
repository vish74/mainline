#
# ObexPush server daemon
#
list ( APPEND obexpushd_SOURCES
  obexpushd.c
  checks.c
  utf.c
  pipe.c
  action/core.c
  action/connect.c
  action/disconnect.c
  action/get.c
  action/put.c
  action/setpath.c
  auth/core.c
  auth/file.c
  io/core.c
  io/internal/common.c
  io/internal/file.c
  io/internal/dir.c
  io/internal/caps.c
  io/script.c
  net/core.c
  net/btobex.c
  net/publish/sdp.c
  net/irobex.c
  net/fdobex.c
  net/fdobex_ctrans.c
)

set ( OBEXPUSHD_VERSION ${VERSION} )
set ( OBEXPUSH_ATD_VERSION 1.0 )
configure_file (
  ${CMAKE_CURRENT_SOURCE_DIR}/version.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/version.h
)

include_directories (
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

option ( USE_LIBGCRYPT "Use gcrypt library" ON )
if ( USE_LIBGCRYPT )
  find_package ( LibGcrypt )
else ( USE_LIBGCRYPT )
  unset ( LIBGCRYPT_FOUND )
endif ( USE_LIBGCRYPT )
if ( LIBGCRYPT_FOUND )
  add_definitions ( -DUSE_LIBGCRYPT )
  list ( APPEND obexpushd_LIBRARIES ${LIBGCRYPT_LIBRARIES} )
endif ( LIBGCRYPT_FOUND )

option ( USE_ICONV "Use iconv functions" OFF )
if ( USE_ICONV )
  find_package ( Iconv )
else ( USE_ICONV )
  unset ( ICONV_FOUND )
endif ( USE_ICONV )
if ( ICONV_FOUND )
  add_definitions ( -DHAVE_ICONV )
  list ( APPEND obexpushd_LIBRARIES ${ICONV_LIBRARIES} )
endif ( ICONV_FOUND )

add_subdirectory ( obex_auth )
list ( APPEND obexpushd_LIBRARIES obex_auth )

add_subdirectory ( x-obex )
list ( APPEND obexpushd_LIBRARIES
  obex-capability
  obex-folder-listing
)

#
# Configure USB gadget support (Linux only)
#
set ( ENABLE_USB_GADGET_SUPPORT OFF )
if ( CMAKE_SYSTEM_NAME STREQUAL "Linux" )
  set ( ENABLE_USB_GADGET_SUPPORT ON )
endif ( CMAKE_SYSTEM_NAME STREQUAL "Linux" )
if ( ENABLE_USB_GADGET_SUPPORT )
  list ( APPEND obexpushd_DEFINITIONS USB_GADGET_SUPPORT )
  list ( APPEND obexpushd_SOURCES
    net/usbgobex.c
    net/usbgobex_ctrans.c
  )
endif ( ENABLE_USB_GADGET_SUPPORT )

#
# Posix spawn is the preferred way to use the script support
#
option ( USE_SPAWN "Use POSIX spawn function instead of fork+exec" ON )
if ( USE_SPAWN )
  list ( APPEND DEFINITIONS USE_SPAWN )
endif ( USE_SPAWN )

#
# Concurrency can be done using threads (preferred) or processes
#
option ( USE_THREADS "Use POSIX threads instead of fork (if supported by system)" ON )
if ( USE_THREADS )
  find_package ( Threads )
  if ( Threads_FOUND AND CMAKE_USE_PTHREADS_INIT )
    list ( APPEND obexpushd_DEFINITIONS USE_THREADS )
    if ( CMAKE_THREAD_LIBS_INIT )
      list ( APPEND obexpushd_LIBRARIES ${CMAKE_THREAD_LIBS_INIT} )
    endif ( CMAKE_THREAD_LIBS_INIT )
  endif ( Threads_FOUND AND CMAKE_USE_PTHREADS_INIT )
endif ( USE_THREADS )

#
# TcpWrapper can be used for access control
#
option ( ENABLE_TCPWRAP "Use the tcp wrapper library to check for restrictions on incoming connections" ON )
if ( ENABLE_TCPWRAP )
  find_package ( TcpWrap )
endif ( ENABLE_TCPWRAP )
if ( TcpWrap_FOUND )
  include_directories ( ${TcpWrap_INCLUDE_DIRS} )
  list ( APPEND obexpushd_DEFINITIONS ENABLE_TCPWRAP )
  list ( APPEND obexpushd_LIBRARIES ${TcpWrap_LIBRARIES} )
endif ( TcpWrap_FOUND )

#
# Extended Attributes can be used for mime type storage
#
find_package( Attr QUIET )
if (Attr_FOUND)
  include_directories ( ${Attr_INCLUDE_DIRS} )
  list ( APPEND obexpushd_DEFINITIONS USE_XATTR )
  list ( APPEND obexpushd_LIBRARIES ${ATTR_LIBRARIES} )
endif (Attr_FOUND)

#
# Absolute necessary: bluetooth and openobex
#
foreach ( i Bluetooth OpenObex )
  find_package ( ${i} REQUIRED )
  if ( ${i}_FOUND )
    include_directories ( ${${i}_INCLUDE_DIRS} )
    if ( ${i}_LIBRARIES )
      list ( APPEND obexpushd_LIBRARIES ${${i}_LIBRARIES} )
    endif ( ${i}_LIBRARIES )
  endif ( ${i}_FOUND )
endforeach ( i )

#
# Check if openobex has TcpObex or the old InObex
#
if ( OpenObex_HAVE_TcpObex )
  list ( APPEND obexpushd_DEFINITIONS OPENOBEX_TCPOBEX=1 )
  list ( APPEND obexpushd_SOURCES net/tcpobex.c )
else ( OpenObex_HAVE_TcpObex )
  list ( APPEND obexpushd_SOURCES net/inobex.c )
endif ( OpenObex_HAVE_TcpObex )

#
# The ObexPushD command line front-end
#
add_executable ( obexpushd ${obexpushd_SOURCES} )
target_link_libraries ( obexpushd ${obexpushd_LIBRARIES} )
list ( APPEND obexpushd_DEFINITIONS DEFINITIONS )
set_property ( TARGET obexpushd PROPERTY
  COMPILE_DEFINITIONS ${obexpushd_DEFINITIONS}
)

#
# The wrapper around ObexPushD to handle AT commands
#
add_executable (obexpush_atd obexpush_atd.c )
set_property ( TARGET obexpush_atd PROPERTY
  COMPILE_DEFINITIONS ${DEFINITIONS}
)

install (
  TARGETS obexpushd obexpush_atd
  RUNTIME DESTINATION bin
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
              GROUP_READ             GROUP_EXECUTE
	      WORLD_READ             WORLD_EXECUTE
)

install (
  FILES storage/file_storage.sh
  DESTINATION ${DOCUMENTATION_INSTALL_DIR}/examples
  PERMISSIONS OWNER_READ OWNER_WRITE
              GROUP_READ
	      WORLD_READ
)

set ( CPACK_PACKAGE_EXECUTABLES "obexpushd" )
if ( UNIX )
  set ( CPACK_STRIP_FILES "bin/obexpushd" )
endif ( UNIX )
