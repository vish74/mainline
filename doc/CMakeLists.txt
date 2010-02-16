
add_custom_target ( doc )

find_package ( Docbook )
if ( Docbook_FOUND )
  include ( ${Docbook_USE_FILE} )

  set ( OBEXPUSHD_XML_FILE "${CMAKE_CURRENT_SOURCE_DIR}/obexpushd.xml" )

  option (BUILD_HELP_MAN "Build manpage application help files" ON)
  if ( BUILD_HELP_MAN )
    docbook_generate ( manpage "${OBEXPUSHD_XML_FILE}" HELP_MAN_FILES )
    foreach ( file ${HELP_MAN_FILES} )
      list ( APPEND OBEXPUSHD_HELP_FILES ${file} )
      get_filename_component ( fileExt ${file} EXT )
      string ( REGEX REPLACE "^[.]" "" fileExt ${fileExt} )
      install (
	FILES ${CMAKE_CURRENT_BINARY_DIR}/${file}
	DESTINATION ${MANPAGE_INSTALL_DIR}/man${fileExt}
	PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
	COMPONENT documentation
	OPTIONAL
      )
    endforeach ( file )
  endif ( BUILD_HELP_MAN )

  option (BUILD_HELP_HTML "Build HTML application help files" OFF)
  if ( BUILD_HELP_HTML )
    include ( UseDocbook )
    docbook_generate ( html "${OBEXPUSHD_XML_FILE}" HELP_HTML_FILES )
    foreach ( file ${HELP_HTML_FILES} )
      list ( APPEND OBEXPUSHD_HELP_FILES ${file} )
      install (
	FILES ${CMAKE_CURRENT_BINARY_DIR}/${file}
	DESTINATION ${DOCUMENTATION_INSTALL_DIR}/html
	PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
	COMPONENT documentation
	OPTIONAL
      )
    endforeach ( file )
  endif ( BUILD_HELP_HTML )

  if ( OBEXPUSHD_HELP_FILES )
    add_custom_target ( obexpushd-doc DEPENDS ${OBEXPUSHD_HELP_FILES} )
    add_dependencies ( obexpushd obexpushd-doc )
    add_dependencies ( doc obexpushd-doc )
  endif ( OBEXPUSHD_HELP_FILES )
endif ( Docbook_FOUND )
