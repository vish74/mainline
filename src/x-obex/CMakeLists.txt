project ( x-obex C )

if ( NOT CMAKE_BUILD_TYPE )
  set ( CMAKE_BUILD_TYPE Release
        CACHE STRING "" FORCE )
endif ( NOT CMAKE_BUILD_TYPE )

if (WIN32 AND NOT UNIX)
  link_libraries ( shlwapi )
endif (WIN32 AND NOT UNIX)

foreach ( type capability folder-listing )
  list ( APPEND obex_${type}_sources
    obex-${type}-app.c
  )

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
    PRIVATE_HEADER DESTINATION include/x-obex
    PERMISSIONS OWNER_READ OWNER_WRITE
                GROUP_READ
                WORLD_READ
  )

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
  target_link_libraries ( obex-${type}
    obex-${type}-lib
  )
endforeach ( type )
