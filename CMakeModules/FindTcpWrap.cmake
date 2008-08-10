
find_path ( TcpWrap_INCLUDE_DIRS tcpd.h PATH_SUFFIXES include )
mark_as_advanced ( TcpWrap_INCLUDE_DIRS )

find_library ( wrap_LIBRARY wrap DOC "TCP wrapper library location" )
mark_as_advanced ( wrap_LIBRARY )
if ( wrap_LIBRARY )
  set ( TcpWrap_LIBRARIES ${wrap_LIBRARY} )
endif ( wrap_LIBRARY )

if ( TcpWrap_INCLUDE_DIRS AND TcpWrap_LIBRARIES )
  set ( TcpWrap_FOUND true )
endif ( TcpWrap_INCLUDE_DIRS AND TcpWrap_LIBRARIES )

if ( NOT TcpWrap_FOUND )
  if ( NOT TcpWrap_FIND_QUIETLY )
    message ( STATUS "Tcp wrapper library not found." )
  endif ( NOT TcpWrap_FIND_QUIETLY )
  if ( TcpWrap_FIND_REQUIRED )
    message ( FATAL_ERROR "" )
  endif ( TcpWrap_FIND_REQUIRED )
endif ( NOT TcpWrap_FOUND )
