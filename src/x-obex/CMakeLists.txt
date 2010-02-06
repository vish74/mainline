project ( x-obex C )

option ( BUILD_X_OBEX_SHARED_LIBS "Build the x-obex libraries as shared libraries" OFF )
if ( BUILD_X_OBEX_SHARED_LIBS )
  set ( X_OBEX_BUILD_TYPE SHARED )
else ( BUILD_X_OBEX_SHARED_LIBS )
  set ( X_OBEX_BUILD_TYPE STATIC )
endif ( BUILD_X_OBEX_SHARED_LIBS )

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

foreach ( lib capability folder-listing )
  add_library ( obex-${lib} ${X_OBEX_BUILD_TYPE}
    obex-${lib}.c
  )
  foreach ( property VERSION SOVERSION PRIVATE_HEADER )
    if ( DEFINED obex-${lib}_${property} )
      set_property ( TARGET obex-${lib} PROPERTY
	${property} ${obex-${lib}_${property}}
      )
    endif ( DEFINED obex-${lib}_${property} )
  endforeach ( property )
  if ( BUILD_X_OBEX_SHARED_LIBS )
    install (
      TARGETS obex-${lib}
      RUNTIME        DESTINATION bin
      LIBRARY        DESTINATION lib
      ARCHIVE        DESTINATION lib
      PRIVATE_HEADER DESTINATION include/x-obex
      PERMISSIONS OWNER_READ OWNER_WRITE
                  GROUP_READ
                  WORLD_READ
    )
  endif ( BUILD_X_OBEX_SHARED_LIBS )
endforeach ( lib )

foreach ( app folder-listing )
  add_executable ( obex-${app}-app
    obex-${app}-app.c
  )
  set_property ( TARGET obex-${app}-app PROPERTY
    OUTPUT_NAME obex-${app}
  )
  install (
    TARGETS obex-${app}-app
    RUNTIME DESTINATION bin
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                GROUP_READ             GROUP_EXECUTE
	        WORLD_READ             WORLD_EXECUTE
  )
  target_link_libraries ( obex-${app}-app
    obex-${app}
  )
endforeach ( app )
