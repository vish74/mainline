project ( x-obex C )

if ( NOT CMAKE_BUILD_TYPE )
  set ( CMAKE_BUILD_TYPE Release
        CACHE STRING "" FORCE )
endif ( NOT CMAKE_BUILD_TYPE )

option ( BUILD_XOBEX_LIBS "Build shared libraries instead of static ones." OFF )

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
    set_target_properties ( obex-${type}-lib
      PROPERTIES
        OUTPUT_NAME "obex-${type}"
    )
  else ( BUILD_XOBEX_LIBS )
    list ( APPEND obex_${type}_sources
      obex-${type}.c
    )
  endif ( BUILD_XOBEX_LIBS )

  add_executable ( obex-${type}
    ${obex_${type}_sources}
  )
  if ( BUILD_XOBEX_LIBS )
    target_link_libraries ( obex-${type}
      obex-${type}-lib
    )
  endif ( BUILD_XOBEX_LIBS )
endforeach ( type )
