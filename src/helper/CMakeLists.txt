project ( x-obex C )

if (WIN32 AND NOT UNIX)
  link_libraries ( shlwapi )
endif (WIN32 AND NOT UNIX)

foreach ( type capability folder-listing )
  add_library ( obex-${type}-lib
    obex-${type}.c
  )
  set_target_properties ( obex-${type}-lib
    PROPERTIES
      OUTPUT_NAME "obex-${type}"
  )

  add_executable ( obex-${type}
    obex-${type}-app.c
  )
  target_link_libraries ( obex-${type}
    obex-${type}-lib
  )
endforeach ( type )
