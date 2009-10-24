
set(SOURCES
  core.c
  md5.c
  obex_auth.c
)
set(HEADERS
  md5.h
  obex_auth.h
)

add_library(obex_auth STATIC
  ${SOURCES}
  ${HEADERS}
)
