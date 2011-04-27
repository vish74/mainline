
set ( SOURCES
  core.c
  obex_auth.c
)
set ( HEADERS
  obex_auth.h
)

if ( LIBGCRYPT_FOUND )
else ( LIBGCRYPT_FOUND )
  list ( APPEND SOURCES md5.c )
  list ( APPEND HEADERS md5.h )
endif ( LIBGCRYPT_FOUND )

add_library(obex_auth STATIC
  ${SOURCES}
  ${HEADERS}
)

if ( LIBGCRYPT_FOUND )
  target_link_libraries ( obex_auth ${LIBGCRYPT_LIBRARIES} )
endif ( LIBGCRYPT_FOUND )
