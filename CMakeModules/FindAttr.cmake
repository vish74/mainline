
find_path ( Attr_INCLUDE_DIRS attr/xattr.h PATH_SUFFIXES include )
mark_as_advanced ( Attr_INCLUDE_DIRS )

find_library ( attr_LIBRARY attr DOC "Extended attributes library location" )
mark_as_advanced ( attr_LIBRARY )
if ( attr_LIBRARY )
  set ( Attr_LIBRARIES ${attr_LIBRARY} )
endif ( attr_LIBRARY )

if ( Attr_INCLUDE_DIRS AND Attr_LIBRARIES )
  set ( Attr_FOUND true )
endif ( Attr_INCLUDE_DIRS AND Attr_LIBRARIES )

if ( NOT Attr_FOUND )
  if ( NOT Attr_FIND_QUIETLY )
    message ( STATUS "Extended attributes (xattr) library not found." )
  endif ( NOT Attr_FIND_QUIETLY )
  if ( Attr_FIND_REQUIRED )
    message ( FATAL_ERROR "" )
  endif ( Attr_FIND_REQUIRED )
endif ( NOT Attr_FOUND )
