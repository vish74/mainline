
find_package ( XmlTo )

if ( XmlTo_FOUND )
  xmlto (
    obexpushd.xml
    MODES man html
    ALL
  )

  foreach ( file ${XMLTO_FILES_man} )
    get_filename_component ( fileExt ${file} EXT )
    string ( REGEX REPLACE "^[.]" "" fileExt ${fileExt} )
    INSTALL (
      FILES ${file}
      DESTINATION share/man/man${fileExt}
      PERMISSIONS OWNER_READ OWNER_WRITE
                  GROUP_READ
                  WORLD_READ
    )
  endforeach ( file ${XMLTO_FILES_man} )
  install (
    FILES ${XMLTO_FILES_html}
    DESTINATION "${DOCUMENTS_DIRECTORY}"
    PERMISSIONS OWNER_READ OWNER_WRITE
                GROUP_READ
                WORLD_READ
  )
endif ( XmlTo_FOUND )
