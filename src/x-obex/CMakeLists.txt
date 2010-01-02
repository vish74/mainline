project ( x-obex C )

option ( X_OBEX_BUILD_SHARED_LIBS "Build the x-obex libraries as shared libraries" OFF )
if ( X_OBEX_BUILD_SHARED_LIBS )
  set ( X_OBEX_BUILD_TYPE SHARED )
else ( X_OBEX_BUILD_SHARED_LIBS )
  set ( X_OBEX_BUILD_TYPE STATIC )
endif ( X_OBEX_BUILD_SHARED_LIBS )

if ( NOT CMAKE_BUILD_TYPE )
  set ( CMAKE_BUILD_TYPE Release
        CACHE STRING "" FORCE )
endif ( NOT CMAKE_BUILD_TYPE )

if (WIN32 AND NOT UNIX)
  link_libraries ( shlwapi )
endif (WIN32 AND NOT UNIX)

set ( obex-capability_VERSION 0.1.0 )
set ( obex-capability_SOVERSION 0 )
set ( obex-capability_PRIVATE_HEADER obex-capability.h )

set ( obex-folder-listing_VERSION 1.0.0 )
set ( obex-folder-listing_SOVERSION 0 )
set ( obex-folder-listing_PRIVATE_HEADER obex-folder-listing.h )

foreach ( type capability folder-listing )
  add_library ( obex-${type}-lib ${X_OBEX_BUILD_TYPE}
    obex-${type}.c
  )
  set_property ( TARGET obex-${type}-lib PROPERTY
    OUTPUT_NAME obex-${type}
  )
  foreach ( property VERSION SOVERSION PRIVATE_HEADER )
    if ( DEFINED obex-${type}_${property} )
      set_property ( TARGET obex-${type}-lib PROPERTY
	${property} ${obex-${type}_${property}}
      )
    endif ( DEFINED obex-${type}_${property} )
  endforeach ( property )

  if ( X_OBEX_BUILD_SHARED_LIBS )
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
  endif ( X_OBEX_BUILD_SHARED_LIBS )

  add_executable ( obex-${type}
    obex-${type}-app.c
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
