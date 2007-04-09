project ( x-obex C )

add_definitions ( -DAPP )

if (WIN32 AND NOT UNIX)
  link_libraries ( shlwapi )
endif (WIN32 AND NOT UNIX)

add_executable ( obex-folder-listing
  obex-folder-listing.c
)

add_executable ( obex-capability
  obex-capability.c
)
