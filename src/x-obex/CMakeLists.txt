project ( x-obex C )

if ( NOT CMAKE_BUILD_TYPE )
  set ( CMAKE_BUILD_TYPE Release
        CACHE STRING "" FORCE )
endif ( NOT CMAKE_BUILD_TYPE )

option ( BUILD_XOBEX_LIBS "Build separate x-obex libraries." OFF )
if ( BUILD_XOBEX_LIBS )
  option ( BUILD_SHARED_LIBS "Build libraries as shared objects." OFF )
endif ( BUILD_XOBEX_LIBS )

if (WIN32 AND NOT UNIX)
  link_libraries ( shlwapi )
endif (WIN32 AND NOT UNIX)

foreach ( type capability folder-listing )
  list ( APPEND obex_${type}_sources
    obex-${type}-app.c
  )
  if ( BUILD_XOBEX_LIBS )
    add_library ( obex-${type}-lib
      obex-${type}.c
    )
    set_property ( TARGET obex-${type}-lib PROPERTY
      OUTPUT_NAME obex-${type}
    )
    set_property ( TARGET obex-${type}-lib PROPERTY
      PRIVATE_HEADER obex-${type}.h
    )
    install (
      TARGETS obex-${type}-lib
      RUNTIME        DESTINATION bin
      LIBRARY        DESTINATION lib
      ARCHIVE        DESTINATION lib
      PRIVATE_HEADER DESTINATION include
      PERMISSIONS OWNER_READ OWNER_WRITE
                  GROUP_READ
	          WORLD_READ
    )
  else ( BUILD_XOBEX_LIBS )
    list ( APPEND obex_${type}_sources
      obex-${type}.c
    )
  endif ( BUILD_XOBEX_LIBS )

  add_executable ( obex-${type}
    ${obex_${type}_sources}
  )
  install (
    TARGETS obex-${type}
    RUNTIME DESTINATION bin
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                GROUP_READ             GROUP_EXECUTE
	        WORLD_READ             WORLD_EXECUTE
  )
  if ( BUILD_XOBEX_LIBS )
    target_link_libraries ( obex-${type}
      obex-${type}-lib
    )
  endif ( BUILD_XOBEX_LIBS )
endforeach ( type )
