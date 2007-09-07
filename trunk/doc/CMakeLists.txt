
set ( CMAKE_MODULE_PATH
  ${CMAKE_CURRENT_SOURCE_DIR}
)

find_package ( XmlTo )

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
  DESTINATION share/doc/${PROJECT_NAME}
  PERMISSIONS OWNER_READ OWNER_WRITE
              GROUP_READ
              WORLD_READ
)
