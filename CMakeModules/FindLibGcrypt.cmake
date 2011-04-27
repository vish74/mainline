
find_program ( LIBGCRYPT_CONFIG_EXECUTABLE libgcrypt-config )
function ( libgcrypt_run_config ARG OUTLIST )
  execute_process ( COMMAND "${LIBGCRYPT_CONFIG_EXECUTABLE}" ${ARG}
    OUTPUT_VARIABLE LIBGCRYPT_CONFIG_OUTPUT
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  # convert the space seperated list to a cmake list
  string ( REPLACE " " ";" ${OUTLIST} "${LIBGCRYPT_CONFIG_OUTPUT}" )
endfunction ( libgcrypt_run_config )

function ( libgcrypt_config_get_libs )
  # Find the proposed libraries to link
  # Those libs are prefixed by -l
  libgcrypt_run_config ( --libs LIBGCRYPT_CONFIG_LIBS )
  # loop over all proposed libs
  foreach ( lib ${LIBGCRYPT_CONFIG_LIBS} )
    string ( REGEX REPLACE "^-l(.*)$" "\\1" lib "${lib}" )
    find_library ( ${lib}_LIBRARY ${lib} )
    mark_as_advanced ( ${lib}_LIBRARY )
    if ( ${lib}_LIBRARY )
      list ( APPEND LIBGCRYPT_LIBRARIES ${${lib}_LIBRARY} )
    endif ( ${lib}_LIBRARY )
  endforeach ( lib )
  set ( LIBGCRYPT_LIBRARIES ${LIBGCRYPT_LIBRARIES} PARENT_SCOPE )
endfunction ( libgcrypt_config_get_libs )

if ( LIBGCRYPTCONFIG_EXECUTABLE )
  libgcrypt_config_get_libs ()
else ( LIBGCRYPTCONFIG_EXECUTABLE )
  find_library ( gcrypt_LIBRARY gcrypt )
  mark_as_advanced ( gcrypt_LIBRARY )
  if ( gcrypt_LIBRARY )
    list ( APPEND LIBGCRYPT_LIBRARIES ${gcrypt_LIBRARY} )
  endif ( gcrypt_LIBRARY )
endif ( LIBGCRYPTCONFIG_EXECUTABLE )

find_path ( LIBGCRYPT_INCLUDE_DIRS gcrypt.h )

mark_as_advanced ( LIBGCRYPT_INCLUDE_DIRS )
if ( LIBGCRYPT_INCLUDE_DIRS AND LIBGCRYPT_LIBRARIES )
  set ( LIBGCRYPT_FOUND true )
endif ( LIBGCRYPT_INCLUDE_DIRS AND LIBGCRYPT_LIBRARIES )

if ( NOT LIBGCRYPT_FOUND )
  if ( NOT LIBGCRYPT_FIND_QUIETLY )
    message ( STATUS "Gcrypt library not found." )
  endif ( NOT LIBGCRYPT_FIND_QUIETLY )
  if ( LIBGCRYPT_FIND_REQUIRED )
    message ( FATAL_ERROR "" )
  endif ( LIBGCRYPT_FIND_REQUIRED )
endif ( NOT LIBGCRYPT_FOUND )
