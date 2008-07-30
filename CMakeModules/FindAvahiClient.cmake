# - Find Avahi client library
#
# The following standard variables get defined:
#  AvahiClient_FOUND:        true if OpenObex was found
#  AvahiClient_INCLUDE_DIRS: the directory that contains the include file
#  AvahiClient_LIBRARIES:    full path to the libraries

find_package ( PkgConfig )
if ( PKG_CONFIG_FOUND )
  pkg_check_modules ( PKGCONFIG_AVAHI_CLIENT avahi-client )
endif ( PKG_CONFIG_FOUND )

if (PKGCONFIG_AVAHI_CLIENT_FOUND )
  set ( AvahiClient_FOUND ${PKGCONFIG_AVAHI_CLIENT_FOUND} )
  set ( AvahiClient_INCLUDE_DIRS ${PKGCONFIG_AVAHI_CLIENT_INCLUDE_DIRS} )
  foreach ( i ${PKGCONFIG_AVAHI_CLIENT_LIBRARIES} )
    find_library ( ${i}_LIBRARY
                   NAMES ${i}
		   PATHS ${PKGCONFIG_AVAHI_CLIENT_LIBRARY_DIRS}
		 )
    list ( APPEND AvahiClient_LIBRARIES ${${i}_LIBRARY} )
    mark_as_advanced ( ${i}_LIBRARY )
  endforeach ( i )
endif (PKGCONFIG_AVAHI_CLIENT_FOUND )

if ( NOT AvahiClient_FOUND )
  if ( NOT AvahiClient_FIND_QUIETLY )
    message ( STATUS "Avahi-client not found.\n" )
  endif ( NOT AvahiClient_FIND_QUIETLY )
  if ( AvahiClient_FIND_REQUIRED )
    message ( STATUS "Avahi-client not found.\n" )
  endif ( AvahiClient_FIND_REQUIRED )
endif ( NOT AvahiClient_FOUND )

### Local Variables:
### mode: cmake
### End:
